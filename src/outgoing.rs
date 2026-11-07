//! A single sleeping task handles external submissions. Enqueue wakes it immediately.
use std::{path::{Path,PathBuf},process::Stdio,sync::Arc,time::Duration};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::io::AsyncWriteExt;
use crate::store::{Store,outbox::{Job,Next,Outcome}};

async fn submit(program:&Path,job:&Job)->Outcome {
    let mut sender = job.from.clone();
    let mut original = None;
    if let Some(path) = &job.forward_blob {
        sender = std::env::var("SSM_FORWARD_FROM").unwrap_or_default();
        if !crate::store::preferences::valid_address(&sender)
            || !crate::store::preferences::permitted_destination(&job.to) {
            return Outcome::Permanent;
        }
        match tokio::fs::File::open(path).await {
            Ok(file) => original = Some(file),
            Err(_) => return Outcome::Temporary,
        }
    }
    let Ok(mut child)=tokio::process::Command::new(program).args(["-i","-f",&sender,"--",&job.to])
        .kill_on_drop(true).stdin(Stdio::piped()).stdout(Stdio::null()).spawn() else {return Outcome::Temporary};
    let result=tokio::time::timeout(Duration::from_secs(45),async {
        let mut pipe=child.stdin.take().unwrap();
        let written = if let Some(mut file) = original {
            let domain = sender.split_once('@').unwrap().1;
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let date = crate::time::format_http_date(stamp as i64).replace("GMT","+0000");
            let mut words = Vec::new();
            let mut chunk = String::new();
            for ch in String::from_utf8_lossy(&job.mime).chars().filter(|c| !c.is_control()).take(160) {
                if chunk.len()+ch.len_utf8()>36 {
                    words.push(format!("=?UTF-8?B?{}?=",STANDARD.encode(&chunk)));
                    chunk.clear();
                }
                chunk.push(ch);
            }
            if !chunk.is_empty(){words.push(format!("=?UTF-8?B?{}?=",STANDARD.encode(chunk)));}
            let subject = words.join("\r\n ");
            let token = job.forward_blob.as_ref().and_then(|p|p.file_stem()).and_then(|s|s.to_str()).unwrap_or("queued");
            let headers = format!("From: {sender}\r\nTo: {}\r\nDate: {date}\r\nMessage-ID: <forward-{}-{token}@{domain}>\r\nSubject: Fwd: {subject}\r\nAuto-Submitted: auto-generated\r\nX-SSM-Forwarded: yes\r\nMIME-Version: 1.0\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=original.eml\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", job.to, job.id);
            pipe.write_all(headers.as_bytes()).await?;
            tokio::io::copy(&mut file,&mut pipe).await.map(|_|())
        } else {
            pipe.write_all(&job.mime).await
        };
        drop(pipe);
        let status=child.wait().await?;
        written.map(|_|status)
    }).await;
    match result {
        Ok(Ok(s)) if s.success()=>Outcome::Accepted,
        Ok(Ok(s)) if s.code()==Some(75)=>Outcome::Temporary,
        Ok(Ok(s)) if s.code()==Some(76)=>Outcome::Unknown,
        Ok(Ok(_))=>Outcome::Permanent,
        _=>Outcome::Unknown,
    }
}
pub async fn run(store:Arc<Store>, program:PathBuf) {
    loop {
        let s=store.clone();
        match tokio::task::spawn_blocking(move||s.next_outgoing()).await {
            Ok(Ok(Next::Send(job)))=>{
                let result=submit(&program,&job).await;
                let s=store.clone();
                if !matches!(tokio::task::spawn_blocking(move||s.finish_outgoing(&job,result)).await,Ok(Ok(()))) {
                    crate::log_error!("outbox: could not record submission result");
                }
            }
            Ok(Ok(Next::Wait(None)))=>{tokio::select!{_=store.outbox_ready.notified()=>(),_=tokio::time::sleep(Duration::from_secs(120))=>()}},
            Ok(Ok(Next::Wait(Some(secs))))=>{tokio::select!{
                _=store.outbox_ready.notified()=>(), _=tokio::time::sleep(Duration::from_secs(secs.min(120)))=>(),
            }}
            _=>{crate::log_error!("outbox: queue unavailable");tokio::time::sleep(Duration::from_secs(30)).await;}
        }
    }
}
