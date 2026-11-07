use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::store::{AccountId, Delivery, Store};
use base64::{Engine, engine::general_purpose::STANDARD};
use super::html::Html;
use super::http::{Method, Request, Response};
use super::pages::{App, signed_in, signed_in_post, see_other, value};
use crate::store::StoreError;

fn program() -> Option<std::path::PathBuf> {
    std::env::var_os("SSM_SENDMAIL").map(std::path::PathBuf::from).filter(|p| p.is_absolute())
}
pub(super) fn enabled() -> bool { program().is_some() }

// Compose accepts one ordinary mailbox. This also rules out header and command options.
fn address(value: &str) -> bool {
    crate::store::preferences::valid_address(value)
}

#[derive(Default)]
struct Reply {
    to: String,
    subject: String,
    parent: Option<String>,
}

fn reply(store: &Store, account: AccountId, uid: u32) -> Result<Reply, StoreError> {
    let mb = store.find_mailbox(account, "INBOX")?.ok_or_else(|| StoreError::NotFound("INBOX".into()))?;
    let mut head = Vec::new();
    store.open_message(mb.id, uid)?.take(64 * 1024).read_to_end(&mut head)?;
    let msg = mail_parser::MessageParser::new().parse_headers(&head)
        .ok_or_else(|| StoreError::InvalidInput("Missing message headers".into()))?;
    let m = msg.root();
    let to = m.reply_to().and_then(|v| v.first()?.address()).or_else(|| m.from()?.first()?.address()).unwrap_or("");
    let subj = m.subject().unwrap_or("");
    let subject = if subj.get(..3).is_some_and(|s| s.eq_ignore_ascii_case("re:")) { subj.to_owned() } else { format!("Re: {subj}") };
    let parent = m.message_id().map(|s| s.trim_matches(['<','>'])).filter(|s| s.len() < 240 && s.contains('@')
        && s.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>'))).map(str::to_owned);
    Ok(Reply { to: to.to_owned(), subject: subject.chars().take(160).collect(), parent })
}

pub(super) async fn handle(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let Some(_) = program() else { return Ok(Response::error(404)) };
    if req.method != Method::Post {
        let Some(me) = signed_in(app, req).await? else { return Ok(see_other("/login")) };
        let uid = match req.query.strip_prefix("reply=") {
            Some(v) => match v.parse::<u32>() { Ok(n) if n > 0 => Some(n), _ => return Ok(Response::error(400)) },
            None => None,
        };
        let id = me.account.id;
        let draft = if let Some(n) = uid {
            match app.blocking(move |s| reply(s, id, n)).await {
                Err(StoreError::NotFound(_)) => return Ok(Response::error(404)),
                r => r?,
            }
        } else { Reply::default() };
        let mut page = Response::html(200, Html::page(if uid.is_some() { "Reply" } else { "Write a message" }, Some(&me.session.csrf), None, |h| {
            h.raw("<p><a href=\"/inbox\">Inbox</a></p><form action=\"/compose\" method=\"post\">").csrf(&me.session.csrf);
            if let Some(n) = uid { h.raw("<input type=\"hidden\" name=\"reply\" value=\"").text(&n.to_string()).raw("\">"); }
            h
                .raw("<label for=\"to\">To</label><input type=\"email\" id=\"to\" name=\"to\" value=\"").text(&draft.to).raw("\" required>")
                .raw("<label for=\"subject\">Subject</label><input id=\"subject\" name=\"subject\" type=\"text\" value=\"").text(&draft.subject).raw("\" maxlength=\"160\">")
                .raw(include_str!("compose.html"));
        }));
        page.headers.push(("Content-Security-Policy", super::http::COMPOSE_CSP.into()));
        return Ok(page);
    }
    let (me, form) = match signed_in_post(app, req, body).await? { Ok(v) => v, Err(r) => return Ok(r) };
    let account = me.account.id;
    let login = me.account.login;
    let parent_uid = match value(&form, "reply") {
        "" => None,
        s => match s.parse::<u32>() { Ok(n) if n > 0 => Some(n), _ => return Ok(Response::error(400)) },
    };
    let to = value(&form, "to").to_owned();
    let subject = value(&form, "subject");
    let body = value(&form, "body");
    if !address(&to) || subject.chars().any(char::is_control) || subject.chars().count() > 160 || body.is_empty() {
        return Ok(Response::error_because(422, "Enter one email address, a short subject, and a message."));
    }
    let csrf = me.session.csrf;
    // Encode UTF-8 in short MIME encoded words, preserving character boundaries.
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in subject.chars() {
        if chunk.len() + c.len_utf8() > 36 {
            words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() { words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk))); }
    let plain_subject = if subject.is_empty() { "(No subject)".to_owned() } else { subject.to_owned() };
    let subject = words.join("\r\n ");
    let body = body.to_owned();
    let html = value(&form, "html").to_owned();
    app.blocking(move |s| {
        if !address(&login) || s.exact_recipient(&login)? != Some(account) {
            return Ok(Response::error_because(422, "Sending requires an address matching your user name."));
        }
        let from = login;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let nonce = getrandom::u64().map_err(|e| std::io::Error::other(e.to_string()))?;
        let id = format!("{:x}.{nonce:016x}@{}", now.as_micros(), from.split_once('@').unwrap().1);
        let date = crate::time::format_http_date(now.as_secs() as i64).replace("GMT", "+0000");
        let mut message = Vec::new();
        write!(message, "Date: {date}\r\nMessage-ID: <{id}>\r\n")?;
        if let Some(n) = parent_uid {
            match reply(s, account, n) {
                Ok(Reply { parent: Some(p), .. }) => write!(message, "In-Reply-To: <{p}>\r\nReferences: <{p}>\r\n")?,
                Ok(_) => (),
                Err(StoreError::NotFound(_)) => return Ok(Response::error(404)),
                Err(e) => return Err(e),
            }
        }
        write!(message, "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n")?;
        write_body(&mut message, &body, &html, nonce)?;
        if let Some(recipient) = s.exact_recipient(&to)? {
            let d = Delivery { key: &id, envelope_from: &from, envelope_to: &to, expected_size: message.len() as u64,
                received_ms: now.as_millis() as i64 };
            let summary_from: String = from.chars().take(120).collect();
            match s.deliver_with_summary(&d, &mut message.as_slice(), Some((recipient, &summary_from, &plain_subject))) {
                Ok(crate::store::DeliveryOutcome::ForwardQueued) => return Ok(Response::html(200,Html::page("Message queued",Some(&csrf),None,|h|{h.raw("<p>Queued for forwarding.</p><a href=\"/inbox\">Return to inbox</a>");}))),
                Err(StoreError::ForwardQueueFull) => return Ok(Response::error_because(429,"Forwarding queue full. Try again later.")),
                Err(StoreError::QuotaExceeded) => return Ok(Response::error_because(422, "The recipient’s mailbox is full.")),
                result => { result?; }
            }
            return Ok(Response::html(200, Html::page("Message delivered", Some(&csrf), None, |h| {
                h.raw("<p>Delivered to ").text(&to).raw(".</p><a href=\"/inbox\">Return to inbox</a>");
            })));
        }
        if !s.enqueue(account,&from,&to,&message)? {
            return Ok(Response::error_because(429,"Outgoing limit reached. Check the outbox and try again later."));
        }
        Ok(Response::html(200, Html::page("Message queued", Some(&csrf), None, |h| {
            h.raw("<p>Your message is in the outgoing queue. <a href=\"/outbox\">Check delivery status</a>.</p><a href=\"/inbox\">Return to inbox</a>");
        })))
    }).await
}

fn write_body(out: &mut Vec<u8>, plain: &str, html: &str, nonce: u64) -> std::io::Result<()> {
    fn part(out: &mut Vec<u8>, subtype: &str, text: &str) -> std::io::Result<()> {
        write!(out, "Content-Type: text/{subtype}; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")?;
        let encoded = STANDARD.encode(text.replace("\r\n", "\n").replace('\n', "\r\n"));
        for line in encoded.as_bytes().chunks(76) {
            out.write_all(line)?;
            out.write_all(b"\r\n")?;
        }
        Ok(())
    }
    if html.is_empty() { return part(out, "plain", plain); }
    let boundary = format!("pm-{nonce:016x}");
    write!(out, "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n")?;
    part(out, "plain", plain)?;
    write!(out, "--{boundary}\r\n")?;
    part(out, "html", html)?;
    write!(out, "--{boundary}--\r\n")
}

#[cfg(test)]
mod tests {
    use super::write_body;
    use mail_parser::MessageParser;

    #[test]
    fn composed_alternatives_round_trip() {
        let plain = "Hello, Zoë!";
        let html = "<p>Hello, <strong>Zoë</strong>!</p>";
        let mut bytes = Vec::new();
        write_body(&mut bytes, plain, html, 1).unwrap();
        let parsed = MessageParser::default().parse(&bytes).unwrap();
        assert_eq!(parsed.body_text(0).as_deref(), Some(plain));
        assert_eq!(parsed.body_html(0).as_deref(), Some(html));
        assert_eq!(parsed.parts().len(), 3);
        bytes.clear();
        write_body(&mut bytes, plain, "", 1).unwrap();
        let parsed = MessageParser::default().parse(&bytes).unwrap();
        assert_eq!(parsed.parts().len(), 1);
        assert_eq!(parsed.body_text(0).as_deref(), Some(plain));
    }
}
