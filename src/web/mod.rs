//! Settings web server: HTTPS on the IMAP certificate, for the home network only unless opened up.
//! `http` parses request heads and writes responses; this module runs the connections, with
//! request limits and timeouts on the injected clock.

use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use crate::inbound::Clock;
use crate::listener::{self, Limits};
use crate::store::Store;
use http::{Method, Request, Response};

mod admin;
mod inbox;
mod compose;
pub mod html;
pub mod http;
mod pages;
pub mod session;
mod setup;

/// The stylesheet's path: versioned, so it can be cached for a year.
pub const CSS_PATH: &str = concat!("/style-", env!("CARGO_PKG_VERSION"), ".css");
const CSS: &[u8] = include_bytes!("style.css");
const PROXIED: &str = "Requests through a proxy are refused: the server cannot tell whether they come from the home network.";

/// Listener settings. `WebConfig::new` gives the design's defaults.
#[derive(Clone)]
pub struct WebConfig {
    /// Implicit TLS on every connection, with the IMAP certificate.
    pub tls: Arc<rustls::ServerConfig>,
    /// Open connections in total and per client IP; past either a new connection is closed at once.
    pub max_conn: usize,
    pub max_conn_per_ip: usize,
    pub handshake_timeout: Duration,
    /// The whole request head must arrive within this; it also bounds writing a response.
    pub head_timeout: Duration,
    /// The body must arrive within this after the head.
    pub body_timeout: Duration,
    /// Time allowed between requests on a kept-alive connection.
    pub keepalive_idle: Duration,
    /// Requests per connection; the last one is answered with `Connection: close`.
    pub max_requests: usize,
    /// Who may connect (by peer address, checked before the TLS handshake).
    pub is_allowed: fn(IpAddr) -> bool,
    /// Serve everyone, whatever `is_allowed` says.
    pub allow_public: bool,
    pub mailbox_only: bool,
}

impl WebConfig {
    pub fn new(tls: Arc<rustls::ServerConfig>) -> WebConfig {
        WebConfig {
            tls,
            max_conn: 32,
            max_conn_per_ip: 8,
            handshake_timeout: Duration::from_secs(10),
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            keepalive_idle: Duration::from_secs(15),
            max_requests: 100,
            is_allowed: is_home_network,
            allow_public: false,
            mailbox_only: false,
        }
    }
}

/// Loopback, private (RFC 1918, RFC 4193) and link-local addresses, IPv4-mapped ones included.
pub fn is_home_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_home_network(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
        },
    }
}

pub struct WebServer {
    addr: SocketAddr,
    setup: Option<String>,
}

impl WebServer {
    /// Spawn the accept loop on the current tokio runtime and return at once. `clock` drives
    /// every timer.
    pub fn start(listener: TcpListener, store: Arc<Store>, config: WebConfig, clock: Arc<dyn Clock>) -> io::Result<WebServer> {
        let addr = listener.local_addr()?;
        if config.mailbox_only && !addr.ip().is_loopback() {
            return Err(io::Error::other("tunnel origin requires a loopback listener"));
        }
        let allowed = (!config.allow_public).then_some(config.is_allowed);
        let limits = Limits { max_conn: config.max_conn, max_conn_per_ip: config.max_conn_per_ip, allowed };
        let (tls, handshake_timeout) = (config.tls.clone(), config.handshake_timeout);
        let (config, conn_clock) = (Arc::new(config), clock.clone());
        let has_admin = store.has_active_admin().map_err(|e| io::Error::other(e.to_string()))?;
        let (link, setup) = match has_admin || config.mailbox_only {
            true => (None, None),
            false => {
                let (link, token) = setup::Link::new(clock.now());
                (Some(link), Some(format!("/setup?t={token}")))
            }
        };
        let app = Arc::new(pages::App::new(store, clock.clone(), link));
        tokio::spawn(listener::accept_loop("web", listener, tls, limits, handshake_timeout, clock, move |tls, peer| {
            serve(tls, peer, config.clone(), conn_clock.clone(), app.clone())
        }));
        Ok(WebServer { addr, setup })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The one-time setup link's path with its token, made at start when no active admin
    /// existed. Only the token's digest is kept to check it against.
    pub fn setup_path(&self) -> Option<String> {
        self.setup.clone()
    }
}

type Conn = TlsStream<TcpStream>;

enum Head {
    Request(Request, usize),
    Refused(u16),
    Gone,
}

async fn serve(mut tls: Conn, peer: SocketAddr, config: Arc<WebConfig>, clock: Arc<dyn Clock>, app: Arc<pages::App>) {
    let mut buf = Vec::new();
    for n in 1..=config.max_requests {
        if n > 1 && buf.is_empty() {
            let more = tokio::select! {
                more = read_more(&mut tls, &mut buf) => more,
                _ = clock.sleep(config.keepalive_idle) => false,
            };
            if !more {
                return;
            }
        }
        let head = tokio::select! {
            head = read_head(&mut tls, &mut buf) => Some(head),
            _ = clock.sleep(config.head_timeout) => None,
        };
        // Err: (response, head_only) to answer before closing.
        let request = match head {
            Some(Head::Gone) => return,
            None => Err((Response::error(408), false)),
            // Behind a proxy the peer address is the proxy's, so the home-network check says nothing.
            Some(Head::Request(req, _)) if req.proxied && !config.allow_public => {
                crate::log_debug!("web: {} refused: a request through a proxy", peer.ip());
                Err((Response::error_because(403, PROXIED), req.method == Method::Head))
            }
            Some(Head::Request(req, len)) => Ok((req, len)),
            Some(Head::Refused(status)) => Err((Response::error(status), false)),
        };
        let (req, len) = match request {
            Ok(r) => r,
            Err((response, head_only)) => {
                respond(&mut tls, &clock, &config, &response, head_only, true).await;
                return;
            }
        };

        let end = len + req.content_length;
        if buf.len() < end {
            let body = tokio::select! {
                complete = fill(&mut tls, &mut buf, end) => Some(complete),
                _ = clock.sleep(config.body_timeout) => None,
            };
            match body {
                None => {
                    respond(&mut tls, &clock, &config, &Response::error(408), false, true).await;
                    return;
                }
                Some(false) => return,
                Some(true) => {}
            }
        }
        let response = if config.mailbox_only {
            inbox::route(&app, &req, &buf[len..end], req.cf_client.unwrap_or(peer.ip())).await
        } else {
            route(&app, &req, &buf[len..end], peer.ip()).await
        };
        buf.drain(..end);

        let close = !req.keep_alive || n == config.max_requests;
        if !respond(&mut tls, &clock, &config, &response, req.method == Method::Head, close).await || close {
            return;
        }
    }
}

async fn route(app: &pages::App, req: &Request, body: &[u8], ip: IpAddr) -> Response {
    if req.method == Method::Post && !req.form {
        return Response::error(415);
    }
    match (req.method, req.path.as_str()) {
        (Method::Get | Method::Head, "/compose.js") => Response {
            status: 200, content_type: "text/javascript; charset=utf-8", cache_control: "no-cache",
            body: Cow::Borrowed(include_bytes!("compose.js")), headers: Vec::new(),
        },
        (Method::Get | Method::Head, CSS_PATH) => Response {
            status: 200,
            content_type: "text/css; charset=utf-8",
            cache_control: "max-age=31536000, immutable",
            body: Cow::Borrowed(CSS),
            headers: Vec::new(),
        },
        _ => pages::handle(app, req, body, ip).await,
    }
}

/// More bytes into `buf`; false on EOF or a transport error.
async fn read_more(tls: &mut Conn, buf: &mut Vec<u8>) -> bool {
    buf.reserve(4096);
    matches!(tls.read_buf(buf).await, Ok(n) if n > 0)
}

async fn read_head(tls: &mut Conn, buf: &mut Vec<u8>) -> Head {
    loop {
        match http::parse_head(buf) {
            Ok(Some((req, len))) => return Head::Request(req, len),
            Err(status) => return Head::Refused(status),
            Ok(None) if !read_more(tls, buf).await => return Head::Gone,
            Ok(None) => {}
        }
    }
}

async fn fill(tls: &mut Conn, buf: &mut Vec<u8>, end: usize) -> bool {
    while buf.len() < end {
        if !read_more(tls, buf).await {
            return false;
        }
    }
    true
}

/// Write `response` (and with `close`, end the TLS session) within the head timeout. False if
/// the client is gone or too slow.
async fn respond(tls: &mut Conn, clock: &Arc<dyn Clock>, config: &WebConfig, response: &Response, head_only: bool, close: bool) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let bytes = response.encode(head_only, close, &crate::time::format_http_date(now));
    let write = async {
        tls.write_all(&bytes).await?;
        if close { tls.shutdown().await } else { tls.flush().await }
    };
    tokio::select! {
        written = write => written.is_ok(),
        _ = clock.sleep(config.head_timeout) => false,
    }
}
