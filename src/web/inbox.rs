use std::io::Read;
use std::net::IpAddr;

use mail_parser::MessageParser;
use super::html::Html;
use super::http::{ Request, Response};
use super::pages::{App, see_other, signed_in};
use crate::store::StoreError;

// This listener has its own sessions. The allowlist also applies to decoded paths.
pub(super) async fn route(app: &App, req: &Request, body: &[u8], ip: IpAddr) -> Response {
    if !matches!(req.path.as_str(), "/" | "/inbox" | "/outbox" | "/message" | "/compose" | "/compose.js" | "/login" | "/logout" | "/me" | "/me/password")
        && req.path != super::CSS_PATH {
        return Response::error(404);
    }
    let mut response = super::route(app, req, body, ip).await;
    if matches!(req.path.as_str(), "/" | "/login") {
        for (name, value) in &mut response.headers {
            if *name == "Location" && matches!(value.as_str(), "/accounts" | "/me") {
                *value = "/inbox".into();
            }
        }
    }
    response
}

pub(super) async fn open(app: &App, req: &Request) -> Result<Response, StoreError> {
    let Some(me) = signed_in(app, req).await? else { return Ok(see_other("/login")) };
    let account = me.account.id;
    let csrf = me.session.csrf;
    if req.path == "/outbox" {
        let rows=app.blocking(move|s|s.outbox_status(account)).await?;
        return Ok(Response::html(200,Html::page("Outbox",Some(&csrf),None,|h|{
            h.raw("<p><a href=\"/inbox\">Inbox</a></p>");
            if rows.is_empty() {h.raw("<p>No external submissions yet.</p>");}
            for (to,state,time) in rows {
                h.raw("<p><strong>").text(&state).raw("</strong> · ").text(&to).raw("<br><small>").text(&crate::time::format_rfc3339(time)).raw("</small></p>");
            }
        })));
    }
    let detail = req.path == "/message";
    let value = if !detail && req.query.is_empty() { i64::from(u32::MAX) + 1 } else {
        let key = if detail { "uid=" } else { "before=" };
        let Some(n) = req.query.strip_prefix(key).and_then(|s| s.parse::<u32>().ok()).filter(|n| *n > 0)
            else { return Ok(Response::error(400)) };
        i64::from(n)
    };
    app.blocking(move |s| {
        let Some(mailbox) = s.find_mailbox(account, "INBOX")? else { return Ok(Response::error(404)) };
        let parser = MessageParser::new().max_depth(20).max_parts(1000).max_encoded_nesting(2);
        if detail {
            let file = match s.open_message(mailbox.id, value as u32) {
                Err(StoreError::NotFound(_)) => return Ok(Response::error(404)),
                result => result?,
            };
            let mut raw = Vec::new();
            file.take(2_097_153).read_to_end(&mut raw)?;
            let page = Html::page("Message", Some(&csrf), None, |h| {
                h.raw("<nav class=\"actions\"><a href=\"/inbox\">Inbox</a>");
                if super::compose::enabled() { h.raw("<a class=\"primary\" href=\"/compose?reply=").text(&value.to_string()).raw("\">Reply</a>"); }
                h.raw("</nav>");
                if raw.len() > 2_097_152 {
                    h.raw("<p>This message is over 2 MB. Open it in your IMAP mail app.</p>");
                } else if let Some(msg) = parser.parse(&raw) {
                    let m = msg.root();
                    h.raw("<h2>").text(m.subject().unwrap_or("(No subject)")).raw("</h2><p>From ")
                        .text(m.from().and_then(|v| v.first()?.address()).unwrap_or("(unknown sender)"))
                        .raw("</p><pre>").text(&m.body_text(0).unwrap_or_else(|| "No text body.".into())).raw("</pre>");
                } else { h.raw("<p>This message could not be displayed.</p>"); }
            });
            return Ok(Response::html(200, page));
        }
        let mut summaries = s.inbox_page(mailbox.id, value)?;
        let older = (summaries.len() > 20).then(|| summaries[19].0);
        summaries.truncate(20);
        Ok(Response::html(200, Html::page("Inbox", Some(&csrf), None, |h| {
            h.raw("<nav class=\"actions\"><a href=\"/me\">Account settings</a><a href=\"/outbox\">Outbox</a>");
            if super::compose::enabled() { h.raw("<a class=\"primary\" href=\"/compose\">Write a message</a>"); }
            h.raw("</nav>");
            if summaries.is_empty() { h.raw("<p>Your inbox is empty.</p>"); }
            h.raw("<ul class=\"messages\">");
            for (uid, sender, subject) in summaries {
                h.raw("<li><a href=\"/message?uid=").text(&uid.to_string()).raw("\"><small>").text(&sender).raw("</small><strong>").text(&subject).raw("</strong></a></li>");
            }
            h.raw("</ul>");
            if let Some(uid) = older {
                h.raw("<a href=\"/inbox?before=").text(&uid.to_string()).raw("\">Older messages</a>");
            }
        })))
    }).await
}
