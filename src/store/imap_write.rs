//! IMAP writes do not route mail or trigger forwarding. Copies share immutable bodies.
use std::{fs,io,path::Path};
use rusqlite::{Connection, OptionalExtension, params};
use super::{blob,Flags,MailboxId,Store,StoreError,now_unix};

impl Store {
    pub fn append_message(&self, mailbox:MailboxId, flags:Flags, date:i64, raw:&[u8])->Result<(),StoreError>{
        use std::io::Write;
        let mut staged=tempfile::NamedTempFile::new_in(self.dir.join("tmp"))?;
        staged.write_all(raw)?;
        self.append_staged(mailbox,flags,date,staged,raw.len() as i64)
    }

    pub fn append_staged(&self,mailbox:MailboxId,flags:Flags,date:i64,staged:tempfile::NamedTempFile,size:i64)->Result<(),StoreError>{
        use std::io::Read;
        let mut preview=Vec::new();
        staged.reopen()?.take(32768).read_to_end(&mut preview)?;
        let (sender,subject)=super::summary(&preview);
        let now=now_unix();
        let name=blob::name(now*1000)?;
        staged.as_file().sync_all()?;
        let mut c=self.writer();
        let tx=c.transaction()?;
        let (account,uid,seq):(i64,u32,i64)=tx.query_row("SELECT account_id,uidnext,highest_modseq+1 FROM mailboxes WHERE id=?1 AND (quota_bytes=0 OR used_bytes+?2<=quota_bytes)",params![mailbox.0,size],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(StoreError::QuotaExceeded)?;
        let rel=format!("blobs/{}/{}/{}",account,crate::time::yyyymm(now),name);
        let dest=self.dir.join(&rel);
        blob::install(staged.path(),&dest,&self.dir.join("blobs"))?;
        let result=(||->Result<(),StoreError>{
            tx.execute("INSERT INTO messages(mailbox_id,uid,blob,size,internal_date,flags,modseq,sender,subject) VALUES(?,?,?,?,?,?,?,?,?)",params![mailbox.0,uid,rel,size,date,flags.bits(),seq,sender,subject])?;
            tx.execute("UPDATE mailboxes SET uidnext=uidnext+1,highest_modseq=?,used_bytes=used_bytes+? WHERE id=?",params![seq,size,mailbox.0])?;
            tx.commit()?; Ok(())
        })();
        if result.is_err(){let _=fs::remove_file(dest);}
        result
    }

    pub fn copy_messages(&self,source:MailboxId,dest:MailboxId,uids:&[u32])->Result<(),StoreError>{
        let mut c=self.writer();
        let tx=c.transaction()?;
        let (mut uid,seq,mut used,quota):(u32,i64,i64,i64)=tx.query_row("SELECT uidnext,highest_modseq+1,used_bytes,quota_bytes FROM mailboxes WHERE id=?",[dest.0],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        for src in uids {
            let size:Option<i64>=tx.query_row("SELECT size FROM messages WHERE mailbox_id=? AND uid=?",params![source.0,src],|r|r.get(0)).optional()?;
            let Some(size)=size else {continue};
            used=used.checked_add(size).ok_or(StoreError::QuotaExceeded)?;
            if quota>0 && used>quota{return Err(StoreError::QuotaExceeded);}
            tx.execute("INSERT INTO messages(mailbox_id,uid,modseq,blob,size,internal_date,flags,sender,subject) SELECT ?,?,?,blob,size,internal_date,flags,sender,subject FROM messages WHERE mailbox_id=? AND uid=?",params![dest.0,uid,seq,source.0,src])?;
            uid=uid.checked_add(1).ok_or_else(||StoreError::InvalidInput("UID space exhausted".into()))?;
        }
        tx.execute("UPDATE mailboxes SET uidnext=?,highest_modseq=?,used_bytes=? WHERE id=?",params![uid,seq,used,dest.0])?;
        tx.commit()?;Ok(())
    }

    pub fn expunge_messages(&self,mb:MailboxId)->Result<(),StoreError>{
        let mut c=self.writer();
        let tx=c.transaction()?;
        let paths=tx.prepare("SELECT DISTINCT blob FROM messages WHERE mailbox_id=? AND flags & 8 != 0")?
            .query_map([mb.0],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if !paths.is_empty(){
            tx.execute("DELETE FROM messages WHERE mailbox_id=? AND flags & 8 != 0",[mb.0])?;
            tx.execute("UPDATE mailboxes SET highest_modseq=highest_modseq+1 WHERE id=?",[mb.0])?;
        }
        tx.commit()?;
        for path in paths { self.remove_unused_blob(&c,&path)?; }
        Ok(())
    }

    pub(super) fn remove_unused_blob(&self,c:&Connection,rel:&str)->Result<(),StoreError>{
        let referenced:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE blob=?1) OR EXISTS(SELECT 1 FROM outbox WHERE forward_blob=?1)",[rel],|r|r.get(0))?;
        if !referenced && Path::new(rel).starts_with("blobs"){
            match fs::remove_file(self.dir.join(rel)){Ok(())=>(),Err(e) if e.kind()==io::ErrorKind::NotFound=>(),Err(e)=>return Err(e.into())}
        }
        Ok(())
    }
}
