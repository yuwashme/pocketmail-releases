use super::{AccountId, Store, StoreError};
use rusqlite::params;

pub fn valid_address(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else { return false };
    !local.is_empty() && local.len() <= 64 && !local.starts_with('-') && value.len() <= 254
        && local.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)))
        && domain.split('.').all(|p| !p.is_empty() && p.len() <= 63 && !p.starts_with('-') && !p.ends_with('-')
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

pub fn external_relay() -> bool {
    std::env::var("SSM_FORWARD_POLICY").as_deref() == Ok("external")
}

pub fn permitted_destination(to: &str) -> bool {
    valid_address(to) && (external_relay() || verified_destinations().iter().any(|v| v==to))
}

pub fn verified_destinations() -> Vec<String> {
    let mut targets: Vec<_> = std::env::var("SSM_VERIFIED_FORWARD_TO").unwrap_or_default()
        .split(',').map(str::trim).filter(|s| valid_address(s)).map(str::to_owned).collect();
    targets.sort();
    targets.dedup();
    targets
}

pub(crate) fn forwardable_headers(preview: &[u8]) -> bool {
    // Fail closed if the bounded preview does not contain the complete header.
    for line in preview.split_inclusive(|b| *b == b'\n') {
        let Some(line) = line.strip_suffix(b"\n") else { return false };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() { return true; }
        if let Some(i) = line.iter().position(|b| *b == b':') {
            if line[..i].eq_ignore_ascii_case(b"Auto-Submitted") {
                let keyword=line[i+1..].split(|b|*b==b';').next().unwrap_or_default().trim_ascii();
                if !keyword.eq_ignore_ascii_case(b"no") {return false;}
            }
            if line[..i].eq_ignore_ascii_case(b"X-SSM-Forwarded") {
                return false;
            }
        }
    }
    false
}

impl Store {
    pub fn mailbox_settings(&self, id: AccountId) -> Result<(i64,i64,Option<String>),StoreError> {
        Ok(self.reader().query_row("SELECT used_bytes, quota_bytes, forward_to FROM mailboxes WHERE account_id=? AND name='INBOX'",
            [id.0], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?)
    }

    pub fn mailbox_overview(&self) -> Result<std::collections::BTreeMap<AccountId,(i64,i64,Option<String>,bool)>,StoreError> {
        let c=self.reader();
        let mut q=c.prepare_cached("SELECT account_id,used_bytes,quota_bytes,forward_to,keep_copy FROM mailboxes WHERE name='INBOX'")?;
        Ok(q.query_map([],|r|Ok((AccountId(r.get(0)?),(r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))))?.collect::<rusqlite::Result<_>>()?)
    }

    pub fn keeps_copy(&self,id:AccountId)->Result<bool,StoreError>{
        Ok(self.reader().query_row("SELECT keep_copy FROM mailboxes WHERE account_id=? AND name='INBOX'",[id.0],|r|r.get(0))?)
    }

    pub fn set_mailbox_settings(&self,id:AccountId, quota:i64, destination:Option<&str>) -> Result<(),StoreError> {
        self.set_forwarding(id,quota,destination,true)
    }

    pub fn set_forwarding(&self,id:AccountId,quota:i64,destination:Option<&str>,keep_copy:bool)->Result<(),StoreError>{
        if quota < 0 { return Err(StoreError::InvalidInput("Enter a positive storage limit.".into())); }
        if let Some(to) = destination {
            if !permitted_destination(to) || self.route(to)?.is_some() {
                return Err(StoreError::InvalidInput("Choose a verified external address.".into()));
            }
        }
        let mut c=self.writer();
        let tx=c.transaction()?;
        if tx.execute("UPDATE mailboxes SET quota_bytes=?, forward_to=?,keep_copy=? WHERE account_id=? AND name='INBOX'",
            params![quota,destination,keep_copy || destination.is_none(),id.0])? != 1 {return Err(StoreError::NotFound("mailbox".into()));}
        tx.execute("UPDATE outbox SET state='Cancelled',forward_blob=CASE WHEN queue_only THEN forward_blob END,mime=NULL WHERE account=? AND forward_blob IS NOT NULL
            AND state='Queued' AND recipient IS NOT ?",params![id.0,destination])?;
        tx.commit()?;
        Ok(())
    }
}
