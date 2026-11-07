//! System flags with mod-sequences, and the \Recent claim.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{MailboxId, Store, StoreError};

/// Bit values are the on-disk encoding of messages.flags (schema v1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    pub const SEEN: Flags = Flags(1);
    pub const ANSWERED: Flags = Flags(2);
    pub const FLAGGED: Flags = Flags(4);
    pub const DELETED: Flags = Flags(8);
    pub const DRAFT: Flags = Flags(16);
    const ALL: u8 = 31;

    pub const fn empty() -> Flags {
        Flags(0)
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, rhs: Flags) -> Flags {
        Flags(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagOp {
    Add,
    Remove,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagUpdate {
    pub uid: u32,
    pub flags: Flags,
    pub modseq: u64,
}

/// Messages with floor < uid <= upto are \Recent for the session that claimed them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecentClaim {
    pub floor: u32,
    pub upto: u32,
}

impl Store {
    /// Returns the current flags and modseq of every requested uid that exists (uid order; unknown
    /// uids skipped). Only messages whose flags change get a new modseq: one new value per call,
    /// shared by all messages it changed (RFC 7162 allows this); highest_modseq = max modseq.
    pub fn store_flags(&self, mailbox: MailboxId, uids: &[u32], op: FlagOp, flags: Flags) -> Result<Vec<FlagUpdate>, StoreError> {
        let mut uids = uids.to_vec();
        uids.sort_unstable();
        uids.dedup();
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let f = flags.0 & Flags::ALL;
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let highest: i64 = tx
            .query_row("SELECT highest_modseq FROM mailboxes WHERE id = ?", [mailbox.0], |r| r.get(0))
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("mailbox {}", mailbox.0)))?;
        let next = highest + 1;
        let mut changed = false;
        let mut out = Vec::with_capacity(uids.len());
        {
            let mut get = tx.prepare_cached("SELECT flags, modseq FROM messages WHERE mailbox_id = ? AND uid = ?")?;
            let mut set = tx.prepare_cached("UPDATE messages SET flags = ?, modseq = ? WHERE mailbox_id = ? AND uid = ?")?;
            for uid in uids {
                let Some((old, modseq)) = get.query_row(params![mailbox.0, uid], |r| Ok((r.get::<_, u8>(0)?, r.get::<_, i64>(1)?))).optional()? else {
                    continue;
                };
                let new = match op {
                    FlagOp::Add => old | f,
                    FlagOp::Remove => old & !f,
                    FlagOp::Replace => f,
                };
                if new == old {
                    out.push(FlagUpdate { uid, flags: Flags(old), modseq: modseq as u64 });
                } else {
                    set.execute(params![new, next, mailbox.0, uid])?;
                    changed = true;
                    out.push(FlagUpdate { uid, flags: Flags(new), modseq: next as u64 });
                }
            }
        }
        if changed {
            tx.execute("UPDATE mailboxes SET highest_modseq = ? WHERE id = ?", params![next, mailbox.0])?;
        }
        tx.commit()?;
        Ok(out)
    }

    /// One transaction: returns {floor: old recent_uid, upto: uidnext-1} and sets recent_uid = upto.
    pub fn claim_recent(&self, mailbox: MailboxId) -> Result<RecentClaim, StoreError> {
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (floor, uidnext): (u32, u32) = tx
            .query_row("SELECT recent_uid, uidnext FROM mailboxes WHERE id = ?", [mailbox.0], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("mailbox {}", mailbox.0)))?;
        let upto = uidnext.saturating_sub(1);
        tx.execute("UPDATE mailboxes SET recent_uid = ? WHERE id = ?", params![upto, mailbox.0])?;
        tx.commit()?;
        Ok(RecentClaim { floor, upto })
    }
}
