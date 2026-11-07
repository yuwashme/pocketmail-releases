//! `Store::deliver`: one Worker hand-off into a mailbox or quarantine.
//!
//! Order: dedupe check, route, tmp write + fsync, rename + dir fsync, one transaction (row,
//! uidnext, highest_modseq, handoff), commit. The caller acks the Worker only after Ok.
//! Crash before the rename: tmp/ is emptied at startup and the message comes again. Between the
//! rename and the commit: an invisible orphan blob (a later fsck can reclaim it). After the commit: only the
//! ack repeats, and the handoff row turns the repeat into AlreadyDelivered.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use rusqlite::{OptionalExtension, TransactionBehavior, params};

#[cfg(feature = "failpoints")]
use super::Failpoint;
use super::blob::{self, Prefix};
use super::{AccountId, MailboxId, Store, StoreError, now_unix};
use crate::time::yyyymm;

pub struct Delivery<'a> {
    /// Hand-off key "msg:<13-digit ms>:<uuid>", the dedupe key.
    pub key: &'a str,
    /// Decoded X-SSM-Envelope-From ("" = null sender).
    pub envelope_from: &'a str,
    /// Decoded X-SSM-Envelope-To.
    pub envelope_to: &'a str,
    /// ms from the key: INTERNALDATE and the blob name/month.
    pub received_ms: i64,
    /// X-SSM-Size: length of the body as read, Return-Path excluded.
    pub expected_size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered { account: AccountId, mailbox: MailboxId, uid: u32 },
    /// Absolute path under <data>/unrouted/.
    Quarantined { path: PathBuf },
    /// Key already in `handoff`: just ack again.
    AlreadyDelivered,
    ForwardQueued,
}

#[cfg(feature = "failpoints")]
macro_rules! failpoint {
    ($store:expr, $fp:ident) => {
        $store.check_failpoint(Failpoint::$fp)?
    };
}
#[cfg(not(feature = "failpoints"))]
macro_rules! failpoint {
    ($store:expr, $fp:ident) => {};
}

/// A header value that can never start a second line: control characters (CR, LF, NUL, …) dropped.
fn header_safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

impl Store {
    pub fn deliver(&self, d: &Delivery<'_>, body: &mut dyn Read) -> Result<DeliveryOutcome, StoreError> {
        self.deliver_with_summary(d, body, None)
    }

    /// A local composer already knows the decoded headers of the MIME it generated.
    pub(crate) fn deliver_with_summary(&self, d: &Delivery<'_>, body: &mut dyn Read, known: Option<(AccountId,&str,&str)>) -> Result<DeliveryOutcome,StoreError> {
        if known.is_none() && self.is_delivered(d.key)? {
            return Ok(DeliveryOutcome::AlreadyDelivered);
        }
        let account = match known { Some((id,_,_)) => Some(id), None => self.route(d.envelope_to)? };
        let name = blob::name(d.received_ms)?;
        let tmp = self.dir.join("tmp").join(&name);
        let prefix = match account {
            Some(_) => Prefix::ReturnPath(format!("Return-Path: <{}>\r\n", header_safe(d.envelope_from)).into_bytes()),
            // Quarantine keeps the envelope, which is otherwise lost once the Worker copy is acked.
            None => Prefix::Always(
                format!(
                    "X-SSM-Envelope-To: {}\r\nX-SSM-Envelope-From: {}\r\n",
                    header_safe(d.envelope_to),
                    header_safe(d.envelope_from)
                )
                .into_bytes(),
            ),
        };
        let (size, preview) = blob::write_tmp(&tmp, prefix, body, d.expected_size, known.is_none())?;
        failpoint!(self, AfterTmpWrite);

        let Some(account) = account else { return self.quarantine(d, &tmp, &name) };

        let rel = format!("blobs/{}/{}/{}", account.0, yyyymm(d.received_ms.div_euclid(1000)), name);
        let dest = self.dir.join(&rel);
        blob::install(&tmp, &dest, &self.dir.join("blobs"))?;
        failpoint!(self, AfterRename);

        let parsed;
        let (sender,subject) = match known {
            Some((_,sender,subject)) => (sender,subject),
            None => { parsed = super::summary(&preview); (parsed.0.as_str(), parsed.1.as_str()) }
        };
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if known.is_none() && tx.prepare_cached("SELECT 1 FROM handoff WHERE key = ?")?.query_row([d.key], |_| Ok(())).optional()?.is_some() {
            // Delivered concurrently since the check above; this copy was never committed.
            drop(tx);
            let _ = fs::remove_file(&dest);
            return Ok(DeliveryOutcome::AlreadyDelivered);
        }
        let inbox: Option<(i64, u32, i64, bool, Option<String>,bool)> = tx.prepare_cached("SELECT id, uidnext, highest_modseq, quota_bytes=0 OR used_bytes+?2<=quota_bytes, forward_to,keep_copy FROM mailboxes WHERE account_id = ?1 AND name = 'INBOX'")?
            .query_row(
                params![account.0, size as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?,r.get(5)?)),
            )
            .optional()?;
        let Some((mailbox, uid, highest, fits, forward_to, keep_copy)) = inbox else {
            drop(tx);
            let _ = fs::remove_file(&dest);
            return Err(StoreError::NotFound(format!("INBOX of account {}", account.0)));
        };
        let forward = forward_to.filter(|_| !d.envelope_from.is_empty()
            && (known.is_some() || super::preferences::forwardable_headers(&preview)));
        // Loop-suppressed messages are kept locally so suppressing a forward cannot discard mail.
        let direct = !keep_copy && forward.is_some();
        if !fits && !direct {
            drop(tx);
            fs::remove_file(&dest)?;
            return Err(StoreError::QuotaExceeded);
        }
        if !direct {
        let modseq = highest + 1;
        tx.prepare_cached(
            "INSERT INTO messages(mailbox_id, uid, blob, size, internal_date, flags, modseq, sender, subject) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)")?.execute(
            params![mailbox, uid, rel, size as i64, d.received_ms.div_euclid(1000), modseq, sender, subject],
        )?;
        tx.prepare_cached("UPDATE mailboxes SET uidnext = ?, highest_modseq = ?, used_bytes=used_bytes+? WHERE id = ?")?.execute(params![uid + 1, modseq, size as i64, mailbox])?;
        }
        // Only Worker hand-offs can be retried with the same key. Local compose generates
        // a fresh Message-ID per POST; indexing it here cannot suppress repeated POSTs.
        if known.is_none() {
            tx.prepare_cached("INSERT INTO handoff(key, delivered_at, mailbox_id, uid) VALUES (?, ?, ?, ?)")?
                .execute(params![d.key, now_unix(), (!direct).then_some(mailbox), (!direct).then_some(uid)])?;
        }

        if let Some(to) = &forward {
            let now = now_unix();
            let allowed: bool = tx.query_row("SELECT count(*) FILTER (WHERE created >= ?2) < 100
                AND count(*) FILTER (WHERE state IN ('Queued','Submitting') OR (queue_only AND forward_blob IS NOT NULL)) < 20
                FROM outbox WHERE account=?1", params![account.0,now-86400], |r|r.get(0))?;
            if direct && !allowed {
                drop(tx);
                fs::remove_file(&dest)?;
                return Err(StoreError::ForwardQueueFull);
            }
            let state = if allowed {"Queued"} else {"Limit reached"};
            tx.execute("INSERT INTO outbox(account,sender,recipient,forward_blob,state,created,due,mime,queue_only)
                VALUES(?, '', ?, ?, ?, ?, ?, ?, ?)", params![account.0,to,allowed.then_some(&rel),state,now,now,
                    allowed.then_some(subject.as_bytes()),direct])?;
        }
        failpoint!(self, BeforeCommit);
        tx.commit()?;
        if forward.is_some() { self.outbox_ready.notify_one(); }
        if direct { return Ok(DeliveryOutcome::ForwardQueued); }
        Ok(DeliveryOutcome::Delivered { account, mailbox: MailboxId(mailbox), uid })
    }

    /// Unknown recipient: move to unrouted/, record the key with NULL ids, log a warning.
    fn quarantine(&self, d: &Delivery<'_>, tmp: &std::path::Path, name: &str) -> Result<DeliveryOutcome, StoreError> {
        let unrouted = self.dir.join("unrouted");
        let dest = unrouted.join(name);
        blob::install(tmp, &dest, &unrouted)?;
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.query_row("SELECT 1 FROM handoff WHERE key = ?", [d.key], |_| Ok(())).optional()?.is_some() {
            drop(tx);
            let _ = fs::remove_file(&dest);
            return Ok(DeliveryOutcome::AlreadyDelivered);
        }
        tx.execute("INSERT INTO handoff(key, delivered_at, mailbox_id, uid) VALUES (?, ?, NULL, NULL)", params![d.key, now_unix()])?;
        tx.commit()?;
        crate::log_warn!("no route for envelope recipient {:?}: quarantined as unrouted/{}", header_safe(d.envelope_to), name);
        Ok(DeliveryOutcome::Quarantined { path: dest })
    }
}
