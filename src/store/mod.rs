//! Protocol-neutral, synchronous mail storage. SQLite is the source of truth for mailboxes, UIDs and
//! flags; message bodies are immutable, byte-exact blob files. This module must not import anything from imap/ or inbound/.
//!
//! Layout under the data dir:
//! ```text
//! ssm.db (+-wal,-shm)  ssm.db.v1[.<unix-seconds>].bak  .lock  tmp/  blobs/<account>/<yyyymm>/<ms>-<16hex>.eml  unrouted/<ms>-<16hex>.eml
//! ```
//! Files are created 0600 and directories 0700.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

mod accounts;
pub mod outbox;
pub mod preferences;
mod blob;
mod deliver;
mod flags;
mod schema;
mod imap_write;

pub use accounts::{Account, Verified, check_login, check_password, normalize_address};
pub use deliver::{Delivery, DeliveryOutcome};
pub use flags::{FlagOp, FlagUpdate, Flags, RecentClaim};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(pub i64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MailboxId(pub i64);

#[derive(Clone, Debug)]
pub struct MailboxInfo {
    pub id: MailboxId,
    pub account: AccountId,
    pub name: String,
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub highest_modseq: u64,
    pub recent_uid: u32,
    pub subscribed: bool,
}

#[derive(Clone, Debug)]
pub struct MessageMeta {
    pub uid: u32,
    /// Path relative to the data dir: "blobs/<account>/<yyyymm>/<ms>-<16hex>.eml".
    pub blob: String,
    /// Blob file length (Return-Path included) = RFC822.SIZE.
    pub size: u64,
    /// Unix seconds = received_ms / 1000 (floor).
    pub internal_date: i64,
    pub flags: Flags,
    pub modseq: u64,
}

/// Test-only crash points inside `deliver`.
#[cfg(feature = "failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failpoint {
    AfterTmpWrite,
    AfterRename,
    BeforeCommit,
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Db(rusqlite::Error),
    /// Another process holds the data dir's exclusive lock (`.lock`).
    Locked(PathBuf),
    SchemaTooNew { found: i64 },
    SizeMismatch { expected: u64, actual: u64 },
    NotFound(String),
    AlreadyExists(String),
    InvalidInput(String),
    /// Password hashing failed (argon2).
    Hash(String),
    /// The change would leave no account that is both admin and enabled.
    QuotaExceeded,
    ForwardQueueFull,
    LastAdmin,
    #[cfg(feature = "failpoints")]
    Failpoint(Failpoint),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "i/o error: {e}"),
            StoreError::Db(e) => write!(f, "database error: {e}"),
            StoreError::Locked(p) => write!(f, "{} is in use by another ssm process", p.display()),
            StoreError::SchemaTooNew { found } => {
                write!(f, "database schema version {found} is newer than this binary knows ({})", schema::VERSION)
            }
            StoreError::SizeMismatch { expected, actual } => write!(f, "size mismatch: expected {expected} bytes, read {actual}"),
            StoreError::NotFound(what) => write!(f, "not found: {what}"),
            StoreError::AlreadyExists(what) => write!(f, "already exists: {what}"),
            StoreError::InvalidInput(why) => write!(f, "invalid input: {why}"),
            StoreError::Hash(why) => write!(f, "password hashing failed: {why}"),
            StoreError::ForwardQueueFull => write!(f,"Forwarding queue is full; try later"),
            StoreError::QuotaExceeded => write!(f, "Mailbox storage limit reached"),
            StoreError::LastAdmin => write!(f, "At least one admin must remain"),
            #[cfg(feature = "failpoints")]
            StoreError::Failpoint(fp) => write!(f, "failpoint {fp:?} hit"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io(e) => Some(e),
            StoreError::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e)
    }
}

pub(crate) fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Per-connection settings: WAL, FULL sync, FKs, 5 s busy wait, 512 KiB cache, no mmap.
const PRAGMAS: &[&str] = &[
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=FULL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
    "PRAGMA cache_size=-512",
    "PRAGMA mmap_size=0",
];

/// Run a statement and discard any rows it returns (some PRAGMAs answer with a row).
fn run(c: &Connection, sql: &str) -> rusqlite::Result<()> {
    let mut st = c.prepare(sql)?;
    let mut rows = st.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

fn open_connection(db: &Path) -> Result<Connection, StoreError> {
    let c = Connection::open(db)?;
    for p in PRAGMAS {
        run(&c, p)?;
    }
    Ok(c)
}

pub(crate) fn mkdirs(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)
}

const READERS: usize = 2;

pub struct Store {
    dir: PathBuf,
    writer: Mutex<Connection>,
    readers: [Mutex<Connection>; READERS],
    next_reader: AtomicUsize,
    argon2_gate: accounts::Gate,
    pub outbox_ready: tokio::sync::Notify,
    /// Held for the life of a daemon store so two daemons never share a data dir.
    _lock: Option<File>,
    #[cfg(feature = "failpoints")]
    failpoint: Mutex<Option<Failpoint>>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding a connection leaves no open transaction (rusqlite rolls back on drop).
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Store {
    /// Creates the data dir and blobs/, tmp/, unrouted/ if missing, takes the exclusive `.lock`,
    /// empties tmp/, opens ssm.db, applies PRAGMAs on every connection and forward migrations to
    /// user_version 2 (a v1 database is first copied to ssm.db.v1[.<unix-seconds>].bak). This is
    /// the daemon's open: a second one on the same dir gets `Locked`.
    pub fn open(data_dir: &Path) -> Result<Store, StoreError> {
        Store::open_with(data_dir, true)
    }

    /// Open for short admin commands (`ssm account …`) while the daemon may be running: no lock
    /// and tmp/ is left alone (it may hold the daemon's in-flight delivery). Only use the account,
    /// address and read methods with it, never `deliver`.
    pub fn open_admin(data_dir: &Path) -> Result<Store, StoreError> {
        Store::open_with(data_dir, false)
    }

    fn open_with(data_dir: &Path, exclusive: bool) -> Result<Store, StoreError> {
        for sub in ["blobs", "tmp", "unrouted"] {
            mkdirs(&data_dir.join(sub))?;
        }
        let lock_file = if exclusive {
            let path = data_dir.join(".lock");
            let f = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(&path)?;
            match f.try_lock() {
                Ok(()) => {}
                Err(fs::TryLockError::WouldBlock) => return Err(StoreError::Locked(data_dir.to_path_buf())),
                Err(fs::TryLockError::Error(e)) => return Err(e.into()),
            }
            blob::empty_dir(&data_dir.join("tmp"))?;
            Some(f)
        } else {
            None
        };

        let db = data_dir.join("ssm.db");
        // Create the file ourselves so it is 0600; SQLite gives -wal/-shm the same mode.
        OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(&db)?;
        let mut writer = open_connection(&db)?;
        schema::migrate(&mut writer, &db)?;
        let readers = [Mutex::new(open_connection(&db)?), Mutex::new(open_connection(&db)?)];

        Ok(Store {
            dir: data_dir.to_path_buf(),
            writer: Mutex::new(writer),
            readers,
            next_reader: AtomicUsize::new(0),
            outbox_ready: tokio::sync::Notify::new(),
            argon2_gate: accounts::Gate::new(match std::env::var("SSM_PASSWORD_JOBS").as_deref() {
                Ok("2") => 2, Ok("1") | Err(_) => 1,
                Ok(_) => return Err(StoreError::InvalidInput("SSM_PASSWORD_JOBS must be 1 or 2".into())),
            }),
            _lock: lock_file,
            #[cfg(feature = "failpoints")]
            failpoint: Mutex::new(None),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.dir
    }

    fn writer(&self) -> MutexGuard<'_, Connection> {
        lock(&self.writer)
    }

    /// A free reader if there is one, else wait on the next in turn.
    fn reader(&self) -> MutexGuard<'_, Connection> {
        for r in &self.readers {
            if let Ok(g) = r.try_lock() {
                return g;
            }
        }
        lock(&self.readers[self.next_reader.fetch_add(1, Ordering::Relaxed) % READERS])
    }

    /// The value of `PRAGMA <name>` on every pooled connection, writer first, as text.
    pub fn pragma(&self, name: &str) -> Result<Vec<String>, StoreError> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(StoreError::InvalidInput(format!("pragma name {name:?}")));
        }
        let sql = format!("PRAGMA {name}");
        let read = |c: &Connection| -> Result<String, StoreError> {
            use rusqlite::types::Value;
            let v = c.query_row(&sql, [], |r| r.get::<_, Value>(0)).optional()?;
            Ok(match v {
                Some(Value::Integer(i)) => i.to_string(),
                Some(Value::Real(f)) => f.to_string(),
                Some(Value::Text(s)) => s,
                Some(Value::Blob(b)) => String::from_utf8_lossy(&b).into_owned(),
                Some(Value::Null) | None => String::new(),
            })
        };
        let mut out = vec![read(&self.writer())?];
        for r in &self.readers {
            out.push(read(&lock(r))?);
        }
        Ok(out)
    }

    // ---- mailboxes -------------------------------------------------------------------------

    const MAILBOX_COLS: &'static str =
        "id, account_id, name, uidvalidity, uidnext, highest_modseq, recent_uid, subscribed";

    fn mailbox_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MailboxInfo> {
        Ok(MailboxInfo {
            id: MailboxId(r.get(0)?),
            account: AccountId(r.get(1)?),
            name: r.get(2)?,
            uidvalidity: r.get(3)?,
            uidnext: r.get(4)?,
            highest_modseq: r.get::<_, i64>(5)? as u64,
            recent_uid: r.get(6)?,
            subscribed: r.get(7)?,
        })
    }

    pub fn mailboxes(&self, account: AccountId) -> Result<Vec<MailboxInfo>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(&format!("SELECT {} FROM mailboxes WHERE account_id = ? ORDER BY name", Self::MAILBOX_COLS))?;
        let rows = st.query_map([account.0], Self::mailbox_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// "INBOX" matches case-insensitively (RFC 3501 5.1); other names exactly.
    pub fn find_mailbox(&self, account: AccountId, name: &str) -> Result<Option<MailboxInfo>, StoreError> {
        let name = if name.eq_ignore_ascii_case("INBOX") { "INBOX" } else { name };
        let c = self.reader();
        let mut st = c.prepare_cached(&format!("SELECT {} FROM mailboxes WHERE account_id = ? AND name = ?", Self::MAILBOX_COLS))?;
        Ok(st.query_row(params![account.0, name], Self::mailbox_row).optional()?)
    }

    pub fn mailbox(&self, id: MailboxId) -> Result<MailboxInfo, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(&format!("SELECT {} FROM mailboxes WHERE id = ?", Self::MAILBOX_COLS))?;
        st.query_row([id.0], Self::mailbox_row).optional()?.ok_or_else(|| StoreError::NotFound(format!("mailbox {}", id.0)))
    }

    /// IMAP SUBSCRIBE / UNSUBSCRIBE (LSUB lists subscribed mailboxes).
    pub fn set_subscribed(&self, mailbox: MailboxId, on: bool) -> Result<(), StoreError> {
        let n = self.writer().execute("UPDATE mailboxes SET subscribed = ? WHERE id = ?", params![on, mailbox.0])?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("mailbox {}", mailbox.0)));
        }
        Ok(())
    }

    // ---- messages --------------------------------------------------------------------------

    /// Every message of the mailbox, in uid order.
    pub fn messages(&self, mailbox: MailboxId) -> Result<Vec<MessageMeta>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(
            "SELECT uid, blob, size, internal_date, flags, modseq FROM messages WHERE mailbox_id = ? ORDER BY uid",
        )?;
        let rows = st.query_map([mailbox.0], |r| {
            Ok(MessageMeta {
                uid: r.get(0)?,
                blob: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                internal_date: r.get(3)?,
                flags: Flags(r.get(4)?),
                modseq: r.get::<_, i64>(5)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Newest first. A cursor keeps the page stable when another message arrives.
    pub fn inbox_page(&self, mailbox: MailboxId, before: i64) -> Result<Vec<(u32,String,String)>, StoreError> {
        use std::io::Read;
        let rows = {
            let c = self.reader();
            let mut st = c.prepare_cached("SELECT uid,sender,subject,blob FROM messages WHERE mailbox_id=? AND uid<? ORDER BY uid DESC LIMIT 21")?;
            st.query_map(params![mailbox.0,before], |r| Ok((r.get::<_,u32>(0)?,r.get::<_,Option<String>>(1)?,
                r.get::<_,Option<String>>(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.into_iter().map(|(uid,sender,subject,blob)| {
            if let (Some(from),Some(title)) = (sender,subject) { return Ok((uid,from,title)); }
            let mut head = Vec::new();
            File::open(self.dir.join(blob))?.take(32768).read_to_end(&mut head)?;
            let (from,title) = summary(&head);
            self.writer().execute("UPDATE messages SET sender=?,subject=? WHERE mailbox_id=? AND uid=? AND subject IS NULL",
                params![from,title,mailbox.0,uid])?;
            Ok((uid,from,title))
        }).collect()
    }

    pub fn open_message(&self, mailbox: MailboxId, uid: u32) -> Result<File, StoreError> {
        let blob: Option<String> = {
            let c = self.reader();
            let mut st = c.prepare_cached("SELECT blob FROM messages WHERE mailbox_id = ? AND uid = ?")?;
            st.query_row(params![mailbox.0, uid], |r| r.get(0)).optional()?
        };
        let blob = blob.ok_or_else(|| StoreError::NotFound(format!("uid {uid} in mailbox {}", mailbox.0)))?;
        Ok(File::open(self.dir.join(blob))?)
    }

    // ---- hand-off bookkeeping --------------------------------------------------------------

    pub fn is_delivered(&self, key: &str) -> Result<bool, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT 1 FROM handoff WHERE key = ?")?;
        Ok(st.exists([key])?)
    }

    /// Deletes handoff rows with delivered_at (unix seconds) < cutoff; returns how many.
    pub fn prune_handoff(&self, cutoff_unix: i64) -> Result<usize, StoreError> {
        let writer = self.writer();
        writer.execute("DELETE FROM outbox WHERE mime IS NULL AND forward_blob IS NULL AND created < ? AND state NOT IN ('Queued','Submitting')", [now_unix()-7*86400])?;
        Ok(writer.execute("DELETE FROM handoff WHERE delivered_at < ?", [cutoff_unix])?)
    }

    #[cfg(feature = "failpoints")]
    pub fn set_failpoint(&self, fp: Option<Failpoint>) {
        *lock(&self.failpoint) = fp;
    }

    /// Err(Failpoint) once if `at` is armed, disarming it.
    #[cfg(feature = "failpoints")]
    fn check_failpoint(&self, at: Failpoint) -> Result<(), StoreError> {
        let mut armed = lock(&self.failpoint);
        if *armed == Some(at) {
            *armed = None;
            return Err(StoreError::Failpoint(at));
        }
        Ok(())
    }
}

fn summary(head: &[u8]) -> (String,String) {
    let msg = mail_parser::MessageParser::new().parse_headers(head);
    let root = msg.as_ref().map(|m| m.root());
    let sender = root.and_then(|m| m.from()?.first()?.address()).unwrap_or("Unknown sender");
    let subject = root.and_then(|m| m.subject()).unwrap_or("(No subject)");
    (sender.chars().take(120).collect(), subject.chars().take(200).collect())
}
