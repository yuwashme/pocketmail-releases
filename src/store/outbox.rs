//! One relay worker per exclusively locked server store. A crash during submission leaves
//! acceptance uncertain, so never automatically repeat an in-flight submission on restart.
use super::{Store, StoreError, AccountId, now_unix};
use rusqlite::{OptionalExtension, params};

pub struct Job {
    pub id: i64, pub from: String, pub to: String, pub mime: Vec<u8>, pub attempts: u32, pub forward_blob: Option<std::path::PathBuf>,
}
pub enum Next { Send(Job), Wait(Option<u64>) }
impl Store {
    pub fn enqueue(&self, account: AccountId, from: &str, to: &str, mime: &[u8]) -> Result<bool, StoreError> {
        let now = now_unix();
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM outbox WHERE mime IS NULL AND forward_blob IS NULL AND created < ? AND state IN ('Accepted','Failed','Check delivery','Cancelled')",[now-7*86400])?;
        let allowed: bool = tx.query_row("SELECT count(*) < 100 AND count(*) FILTER(WHERE state IN ('Queued','Submitting')) < 20
            FROM outbox WHERE account=? AND created>=?",params![account.0,now-86400],|r|r.get(0))?;
        if !allowed {return Ok(false);}
        tx.execute("INSERT INTO outbox(account,sender,recipient,mime,state,created,due) VALUES(?,?,?,?,'Queued',?,?)",
            params![account.0,from,to,mime,now,now])?;
        tx.commit()?;
        self.outbox_ready.notify_one();
        Ok(true)
    }
    pub fn outbox_status(&self, account: AccountId) -> Result<Vec<(String,String,i64)>, StoreError> {
        let c=self.reader();
        let mut q=c.prepare_cached("SELECT recipient,state,created FROM outbox WHERE account=? ORDER BY created DESC,id DESC LIMIT 50")?;
        Ok(q.query_map([account.0],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<rusqlite::Result<_>>()?)
    }
    pub fn recover_outbox(&self) -> Result<(), StoreError> {
        self.writer().execute("UPDATE outbox SET state='Check delivery' WHERE state='Submitting'",[])?;
        self.clean_accepted()
    }

    fn clean_accepted(&self)->Result<(),StoreError>{
        let c=self.writer();
        let mut q=c.prepare_cached("SELECT id,forward_blob FROM outbox WHERE state='Accepted' AND forward_blob IS NOT NULL")?;
        let files=q.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for (id,path) in files {
            let used:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE blob=?1) OR EXISTS(SELECT 1 FROM outbox WHERE id!=?2 AND forward_blob=?1)",params![path,id],|r|r.get(0))?;
            if !used {
                match std::fs::remove_file(self.dir.join(&path)) {
                    Ok(())=>(),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),Err(e)=>return Err(e.into()),
                }
            }
            c.execute("UPDATE outbox SET forward_blob=NULL WHERE id=?",[id])?;
        }
        Ok(())
    }
    pub fn next_outgoing(&self) -> Result<Next, StoreError> {
        let mut c=self.writer();
        let tx=c.transaction()?;
        let now=now_unix();
        let job=tx.query_row("SELECT id,sender,recipient,mime,attempts,forward_blob FROM outbox WHERE state='Queued' AND due<=? ORDER BY due,id LIMIT 1",
            [now],|r|Ok(Job{id:r.get(0)?,from:r.get(1)?,to:r.get(2)?,mime:r.get::<_,Option<Vec<u8>>>(3)?.unwrap_or_default(), forward_blob:r.get::<_,Option<String>>(5)?.map(|p|self.dir.join(p)),attempts:r.get::<_,u32>(4)?+1})).optional()?;
        if let Some(job)=job {
            tx.execute("UPDATE outbox SET state='Submitting',attempts=attempts+1 WHERE id=?",[job.id])?;
            tx.commit()?;return Ok(Next::Send(job));
        }
        let due: Option<i64>=tx.query_row("SELECT min(due) FROM outbox WHERE state='Queued'",[],|r|r.get(0))?;
        Ok(Next::Wait(due.map(|d|d.saturating_sub(now).max(0) as u64)))
    }
    pub fn finish_outgoing(&self, job:&Job, result:Outcome) -> Result<(), StoreError> {
        let (state,delay)=match result {
            Outcome::Accepted=>("Accepted",0), Outcome::Unknown=>("Check delivery",0),
            Outcome::Temporary if job.attempts<5=>("Queued",30i64 << (job.attempts-1)),
            _=>("Failed",0),
        };
        self.writer().execute("UPDATE outbox SET state=?1,due=?2,mime=CASE WHEN ?1!='Accepted' THEN mime END WHERE id=?3",
            params![state,now_unix()+delay,job.id])?;
        if state=="Accepted" && job.forward_blob.is_some() {self.clean_accepted()?;}
        Ok(())
    }
}
pub enum Outcome { Accepted, Temporary, Permanent, Unknown }
