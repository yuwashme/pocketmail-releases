//! IMAP4rev1 server.
//!
//! Implicit TLS only. `ImapServer::start` runs the shared accept loop (`crate::listener`),
//! `session` the per-connection state machine and command framer, `fetch` / `bodystructure` the
//! FETCH data items. Commands are decoded with imap-codec; responses are written by hand.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::listener::{self, Limits};
use crate::store::Store;

pub mod bodystructure;
pub mod fetch;
pub mod search;
pub mod session;
mod wire;

/// The same clock trait the poller uses; every IMAP timer (autologout, the delay after a failed
/// login) goes through it so tests can drive time by hand.
pub use crate::inbound::Clock;

/// A TLS handshake that has not finished after this long is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Listener settings. `ServerConfig::new` gives the design's defaults.
#[derive(Clone)]
pub struct ServerConfig {
    /// Implicit TLS on every connection (no STARTTLS, no plaintext).
    pub tls: Arc<rustls::ServerConfig>,
    /// Open connections in total; past it new connections get `* BYE` (or are closed) at once.
    pub max_conn: usize,
    /// Open connections per client IP; same treatment past it.
    pub max_conn_per_ip: usize,
    /// Longest command line, CRLF excluded (64 KiB). Over it: BAD, then close.
    pub max_line: usize,
    /// Longest literal (64 KiB). Over it: BAD without a `+` continuation, then close.
    pub max_literal: usize,
    /// Idle time before `* BYE` and close (30 min, both before and after login).
    pub autologout: Duration,
    /// Delay before `NO [AUTHENTICATIONFAILED]` (2 s).
    pub auth_failure_delay: Duration,
    /// BAD responses before login that close the connection: on the 3rd BAD the server closes (3).
    pub max_bad_before_login: u32,
}

impl ServerConfig {
    pub fn new(tls: Arc<rustls::ServerConfig>) -> ServerConfig {
        ServerConfig {
            tls,
            max_conn: 100,
            max_conn_per_ip: 10,
            max_line: 64 * 1024,
            max_literal: 64 * 1024,
            autologout: Duration::from_secs(30 * 60),
            auth_failure_delay: Duration::from_secs(2),
            max_bad_before_login: 3,
        }
    }
}

/// A running listener. Dropping it does not stop the accept loop (the process owns it).
pub struct ImapServer {
    addr: SocketAddr,
}

impl ImapServer {
    /// Spawn the accept loop on the current tokio runtime and return at once. `listener` is
    /// already bound (tests bind 127.0.0.1:0); `clock` drives every timer.
    pub fn start(listener: tokio::net::TcpListener, store: Arc<Store>, config: ServerConfig, clock: Arc<dyn Clock>) -> io::Result<ImapServer> {
        let addr = listener.local_addr()?;
        tokio::spawn(accept_loop(listener, store, Arc::new(config), clock));
        Ok(ImapServer { addr })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

async fn accept_loop(listener: tokio::net::TcpListener, store: Arc<Store>, config: Arc<ServerConfig>, clock: Arc<dyn Clock>) {
    let limits = Limits { max_conn: config.max_conn, max_conn_per_ip: config.max_conn_per_ip, allowed: None };
    let (tls, session_clock) = (config.tls.clone(), clock.clone());
    listener::accept_loop("imap", listener, tls, limits, HANDSHAKE_TIMEOUT, clock, move |tls, peer| {
        session::run(tls, peer, store.clone(), config.clone(), session_clock.clone())
    })
    .await
}
