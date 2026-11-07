//! Implicit-TLS accept loop shared by the listeners: an optional peer address check, connection
//! caps (total and per client IP) and the TLS handshake timeout. Each connection that completes its handshake goes to a handler.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use crate::inbound::Clock;

/// Who may connect and how many at once. A refused peer, or one past either cap, is closed before
/// any TLS.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_conn: usize,
    pub max_conn_per_ip: usize,
    /// Peer addresses allowed to connect; None: every address.
    pub allowed: Option<fn(IpAddr) -> bool>,
}

/// Open connections: (total, per IP).
type Slots = Arc<Mutex<(usize, HashMap<IpAddr, usize>)>>;

/// One taken connection slot; released on drop.
struct SlotGuard {
    slots: Slots,
    ip: IpAddr,
}

impl SlotGuard {
    fn take(slots: &Slots, ip: IpAddr, limits: Limits) -> Option<SlotGuard> {
        let mut s = slots.lock().unwrap_or_else(|e| e.into_inner());
        let per_ip = s.1.get(&ip).copied().unwrap_or(0);
        if s.0 >= limits.max_conn || per_ip >= limits.max_conn_per_ip {
            return None;
        }
        s.0 += 1;
        s.1.insert(ip, per_ip + 1);
        Some(SlotGuard { slots: slots.clone(), ip })
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        s.0 = s.0.saturating_sub(1);
        if let Some(n) = s.1.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                s.1.remove(&self.ip);
            }
        }
    }
}

/// Accept forever. Each connection holds its slot until `handler`'s future ends; `name` prefixes
/// the log lines. A TLS handshake not finished after `handshake_timeout` (on `clock`) is dropped.
pub async fn accept_loop<H, F>(
    name: &'static str,
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    limits: Limits,
    handshake_timeout: Duration,
    clock: Arc<dyn Clock>,
    handler: H,
) where
    H: Fn(TlsStream<TcpStream>, SocketAddr) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let slots: Slots = Arc::new(Mutex::new((0, HashMap::new())));
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let handler = Arc::new(handler);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Out of file descriptors and the like: back off briefly instead of spinning.
                crate::log_warn!("{name}: accept failed: {e}");
                let c = clock.clone();
                c.sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if limits.allowed.is_some_and(|allowed| !allowed(peer.ip())) {
            crate::log_debug!("{name}: connection from {} refused: not on the home network", peer.ip());
            drop(tcp);
            continue;
        }
        let Some(slot) = SlotGuard::take(&slots, peer.ip(), limits) else {
            crate::log_info!("{name}: connection from {} refused: connection cap reached", peer.ip());
            drop(tcp); // over the cap: close at once, before any TLS
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let (acceptor, clock, handler) = (acceptor.clone(), clock.clone(), handler.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let handshake = tokio::select! {
                r = acceptor.accept(tcp) => r.ok(),
                _ = clock.sleep(handshake_timeout) => None,
            };
            let Some(tls) = handshake else {
                crate::log_debug!("{name}: TLS handshake with {} failed", peer.ip());
                return;
            };
            handler(tls, peer).await;
        });
    }
}
