//! Schemas v1, v2 and forward-only migrations (`PRAGMA user_version`).

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, TransactionBehavior};

use super::StoreError;

/// The newest schema this binary knows.
pub const VERSION: i64 = 6;

const V1: &str = "
CREATE TABLE accounts(
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INT,
    disabled INT DEFAULT 0
);
-- 'test@example.com' or the catch-all '@example.com', lowercase
CREATE TABLE addresses(
    address TEXT PRIMARY KEY,
    account_id INT NOT NULL REFERENCES accounts
) WITHOUT ROWID;
CREATE TABLE mailboxes(
    id INTEGER PRIMARY KEY,
    account_id INT NOT NULL REFERENCES accounts,
    name TEXT NOT NULL,
    uidvalidity INT NOT NULL,
    uidnext INT NOT NULL DEFAULT 1,
    highest_modseq INT NOT NULL DEFAULT 1,
    recent_uid INT NOT NULL DEFAULT 0,
    subscribed INT NOT NULL DEFAULT 1,
    UNIQUE(account_id, name)
);
-- flags: 1 Seen 2 Answered 4 Flagged 8 Deleted 16 Draft
CREATE TABLE messages(
    mailbox_id INT NOT NULL REFERENCES mailboxes,
    uid INT NOT NULL,
    blob TEXT NOT NULL,
    size INT NOT NULL,
    internal_date INT NOT NULL,
    flags INT NOT NULL DEFAULT 0,
    modseq INT NOT NULL,
    PRIMARY KEY(mailbox_id, uid)
) WITHOUT ROWID;
-- one row per Worker hand-off key; NULL ids = quarantined to unrouted/
CREATE TABLE handoff(
    key TEXT PRIMARY KEY,
    delivered_at INT NOT NULL,
    mailbox_id INT,
    uid INT
) WITHOUT ROWID;
";

const V2: &str = "
ALTER TABLE accounts ADD COLUMN admin INT NOT NULL DEFAULT 0;
-- changes on every password change; a web session started under another stamp is over
ALTER TABLE accounts ADD COLUMN auth_stamp INT NOT NULL DEFAULT 0;
";

fn user_version(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
}

/// Bring the database at `db` up to `VERSION`, refusing one that is newer. A v1 database is first
/// copied to `ssm.db.v1.bak` next to it, or to `ssm.db.v1.<unix-seconds>.bak` if that is taken.
pub fn migrate(c: &mut Connection, db: &Path) -> Result<(), StoreError> {
    let found = user_version(c)?;
    if found > VERSION {
        return Err(StoreError::SchemaTooNew { found });
    }
    if found == VERSION {
        return Ok(());
    }
    // IMMEDIATE: an admin command and the daemon may race to create a fresh database.
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = user_version(&tx)?;
    if found > VERSION {
        return Err(StoreError::SchemaTooNew { found });
    }
    if found < 1 {
        tx.execute_batch(V1)?;
    }
    if found == 1 {
        backup_v1(db)?;
    }
    if found < 2 {
        tx.execute_batch(V2)?;
    }
    if found < 3 {
        tx.execute_batch("ALTER TABLE messages ADD COLUMN sender TEXT;
            ALTER TABLE messages ADD COLUMN subject TEXT;
            CREATE TABLE outbox(id INTEGER PRIMARY KEY, account INTEGER NOT NULL REFERENCES accounts,
                sender TEXT NOT NULL, recipient TEXT NOT NULL, mime BLOB, state TEXT NOT NULL,
                created INTEGER NOT NULL, due INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX outbox_due ON outbox(state,due);
            CREATE INDEX outbox_account ON outbox(account,created);")?;
    }
    if found < 4 {
        tx.execute_batch("ALTER TABLE mailboxes ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE mailboxes ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE mailboxes ADD COLUMN forward_to TEXT;
            UPDATE mailboxes SET used_bytes=(SELECT coalesce(sum(size),0) FROM messages WHERE mailbox_id=mailboxes.id);
            CREATE TRIGGER release_mailbox_space AFTER DELETE ON messages BEGIN
                UPDATE mailboxes SET used_bytes=used_bytes-old.size WHERE id=old.mailbox_id;
            END;
            ALTER TABLE outbox ADD COLUMN forward_blob TEXT;")?;
    }
    if found < 5 {
        // Replace the column so every mailbox insertion gets the same default in SQLite.
        tx.execute_batch("ALTER TABLE mailboxes RENAME COLUMN quota_bytes TO previous_quota;
            ALTER TABLE mailboxes ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 1073741824;
            UPDATE mailboxes SET quota_bytes=previous_quota WHERE previous_quota>0;
            ALTER TABLE mailboxes DROP COLUMN previous_quota;")?;
    }
    if found < 6 {
        tx.execute_batch("ALTER TABLE mailboxes ADD COLUMN keep_copy INTEGER NOT NULL DEFAULT 1;
            ALTER TABLE outbox ADD COLUMN queue_only INTEGER NOT NULL DEFAULT 0;")?;
    }
    tx.pragma_update(None, "user_version", VERSION)?;
    tx.commit()?;
    Ok(())
}

/// `VACUUM INTO` a 0600 temp file through a second connection (the caller holds the write lock, so
/// this is the last committed v1 state), fsync, then rename into place and fsync the directory.
fn backup_v1(db: &Path) -> Result<(), StoreError> {
    let mut backup = db.with_extension("db.v1.bak");
    if backup.exists() {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        backup = db.with_extension(format!("db.v1.{secs}.bak"));
    }
    let tmp = db.with_extension("db.v1.bak.tmp");
    // VACUUM INTO accepts an empty file, which keeps the mode set here.
    OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp)?;
    let src = Connection::open(db)?;
    src.execute("VACUUM INTO ?", [tmp.to_string_lossy()])?;
    drop(src);
    File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, &backup)?;
    let dir = db.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(dir)?.sync_all()?;
    Ok(())
}
