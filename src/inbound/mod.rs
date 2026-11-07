//! Inbound puller: list the Worker every `interval` (>= 120 s on KV), list again at once while
//! `complete` is false and the round made progress, fetch -> `store::deliver` -> DELETE only after the SQLite commit.
//! Failed passes back off exponentially to 30 min. A re-listed key that is already delivered is
//! never fetched again and gets DELETE at most once per 10 min.

pub mod http;
pub mod worker_api;

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::store::{Delivery, DeliveryOutcome, Store, StoreError};
use crate::{log_error, log_info, log_warn};
use worker_api::{ApiError, Fetch, WorkerApi};

/// Upper bound of the error backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30 * 60);
/// A delivered key that is listed again gets another DELETE at most this often.
pub const REDELETE_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// A 401 (wrong token) is logged at most this often.
const UNAUTHORIZED_LOG_INTERVAL: Duration = Duration::from_secs(3600);

/// Wait after a pass: `interval` after a successful pass; after `n >= 1` consecutive failed passes
/// `min(interval * 2^n, MAX_BACKOFF)`.
pub fn backoff_delay(interval: Duration, consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return interval;
    }
    2u32.checked_pow(consecutive_failures)
        .and_then(|f| interval.checked_mul(f))
        .map_or(MAX_BACKOFF, |d| d.min(MAX_BACKOFF))
}

/// Time source of the poll loop. Production uses `TokioClock`; tests use a simulated clock so
/// 24 hours of polling run in seconds without tokio's paused time (whose auto-advance fires
/// timers while real loopback I/O is still in flight).
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary origin.
    fn now(&self) -> Duration;
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// `tokio::time::Instant` and `tokio::time::sleep`.
pub struct TokioClock;

impl Clock for TokioClock {
    fn now(&self) -> Duration {
        static ORIGIN: OnceLock<tokio::time::Instant> = OnceLock::new();
        ORIGIN.get_or_init(tokio::time::Instant::now).elapsed()
    }
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// What one `poll_once` did. A key counts in exactly one of delivered, quarantined,
/// already_delivered, gone, skipped, failed; `deleted` counts successful DELETEs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// GET /messages requests made in this pass.
    pub lists: u32,
    pub delivered: u32,
    pub quarantined: u32,
    /// Listed again although already in `handoff` (not fetched again).
    pub already_delivered: u32,
    /// 404 on fetch.
    pub gone: u32,
    /// Key not in the `msg:<13 digits>:<id>` format: not fetched, not deleted (KV TTL removes it).
    pub skipped: u32,
    /// Fetch or store error: not deleted, retried next pass.
    pub failed: u32,
    pub deleted: u32,
}

pub struct Poller {
    api: WorkerApi,
    store: Arc<Store>,
    interval: Duration,
    clock: Arc<dyn Clock>,
    /// `<data>/tmp`: downloads land here (emptied by `Store::open` after a crash).
    tmp: PathBuf,
    /// Clock time of the last DELETE attempt per key, kept for REDELETE_INTERVAL.
    deleted_at: HashMap<String, Duration>,
}

impl Poller {
    /// Downloads go to `<store data dir>/tmp`. Clock: `TokioClock`.
    pub fn new(api: WorkerApi, store: Arc<Store>, interval: Duration) -> Poller {
        let tmp = store.data_dir().join("tmp");
        Poller { api, store, interval, clock: Arc::new(TokioClock), tmp, deleted_at: HashMap::new() }
    }

    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Poller {
        Poller { clock, ..self }
    }

    /// One pass, no sleeping. Err only when a list request fails (network, 401, 5xx, bad JSON);
    /// per-message problems are counted in the report.
    pub async fn poll_once(&mut self) -> Result<PassReport, ApiError> {
        let now = self.clock.now();
        self.deleted_at.retain(|_, t| now.saturating_sub(*t) < REDELETE_INTERVAL);
        let mut report = PassReport::default();
        loop {
            let listing = self.api.list().await?;
            report.lists += 1;
            // Key order = arrival order = UID order; not trusted from the Worker.
            let mut ids = listing.ids;
            ids.sort();
            ids.dedup();
            let deleted_before = report.deleted;
            for id in &ids {
                self.handle(id, &mut report).await;
            }
            // complete:false => list again at once, but only if this round freed KV space;
            // otherwise the next pass retries (no spinning on the KV list quota).
            if listing.complete || report.deleted == deleted_before {
                return Ok(report);
            }
        }
    }

    async fn handle(&mut self, id: &str, report: &mut PassReport) {
        let Some(received_ms) = worker_api::parse_key(id) else {
            report.skipped += 1;
            return;
        };
        match self.store.is_delivered(id) {
            Ok(true) => {
                report.already_delivered += 1;
                self.ack(id, report).await;
                return;
            }
            Ok(false) => {}
            Err(e) => {
                log_error!("inbound {id}: store: {e}");
                report.failed += 1;
                return;
            }
        }
        let m = match self.api.fetch(id, &self.tmp).await {
            Ok(Fetch::Message(m)) => m,
            Ok(Fetch::Gone) => {
                report.gone += 1;
                return;
            }
            Err(e) => {
                log_warn!("inbound {id}: fetch: {e}");
                report.failed += 1;
                return;
            }
        };
        // SQLite and fsync block: off the runtime thread. The download is removed when `m` drops.
        let store = self.store.clone();
        let key = id.to_string();
        let outcome = tokio::task::spawn_blocking(move || -> Result<DeliveryOutcome, StoreError> {
            let mut body = m.body.open()?;
            let d = Delivery {
                key: &key,
                envelope_from: &m.envelope_from,
                envelope_to: &m.envelope_to,
                received_ms,
                expected_size: m.size,
            };
            store.deliver(&d, &mut body)
        })
        .await;
        match outcome {
            Ok(Ok(DeliveryOutcome::ForwardQueued)) => report.delivered += 1,
            Ok(Ok(DeliveryOutcome::Delivered { uid, .. })) => {
                log_info!("inbound {id}: delivered, uid {uid}");
                report.delivered += 1;
            }
            Ok(Ok(DeliveryOutcome::Quarantined { path })) => {
                log_warn!("inbound {id}: no account for the recipient, quarantined in {}", path.display());
                report.quarantined += 1;
            }
            Ok(Ok(DeliveryOutcome::AlreadyDelivered)) => report.already_delivered += 1,
            Ok(Err(e)) => {
                log_error!("inbound {id}: delivery failed, will retry: {e}");
                report.failed += 1;
                return;
            }
            Err(e) => {
                log_error!("inbound {id}: delivery task failed, will retry: {e}");
                report.failed += 1;
                return;
            }
        }
        // Only now, after the commit, may the Worker forget its copy.
        self.ack(id, report).await;
    }

    /// DELETE `id` unless a DELETE for it was tried less than REDELETE_INTERVAL ago.
    async fn ack(&mut self, id: &str, report: &mut PassReport) {
        let now = self.clock.now();
        if self.deleted_at.get(id).is_some_and(|t| now.saturating_sub(*t) < REDELETE_INTERVAL) {
            return;
        }
        self.deleted_at.insert(id.to_string(), now);
        match self.api.delete(id).await {
            Ok(()) => report.deleted += 1,
            Err(e) => log_warn!("inbound {id}: DELETE failed, retry in 10 min: {e}"),
        }
    }

    /// `poll_once`, then sleep `backoff_delay(interval, consecutive failed passes)` on the clock;
    /// forever.
    pub async fn run(mut self) {
        let mut failures = 0u32;
        let mut unauthorized_logged: Option<Duration> = None;
        loop {
            match self.poll_once().await {
                Ok(_) => failures = 0,
                Err(e) => {
                    failures = failures.saturating_add(1);
                    let wait = backoff_delay(self.interval, failures).as_secs();
                    if matches!(e, ApiError::Unauthorized) {
                        let now = self.clock.now();
                        if unauthorized_logged.is_none_or(|t| now.saturating_sub(t) >= UNAUTHORIZED_LOG_INTERVAL) {
                            unauthorized_logged = Some(now);
                            log_error!("inbound: the Worker refused the pull token (401); next try in {wait} s");
                        }
                    } else {
                        log_warn!("inbound: list failed ({e}); next try in {wait} s");
                    }
                }
            }
            self.clock.sleep(backoff_delay(self.interval, failures)).await;
        }
    }
}
