//! The one-time setup link, made at start while no active admin exists. It makes an existing
//! account admin (with that account's password, through the sign-in limit) or creates a new
//! admin, then signs that admin in. Only the token's digest is kept; the link is valid for an
//! hour, used up by the first success, and dead as soon as any active admin exists.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::MutexGuard;

use super::admin::LOGIN_RULES;
use super::html::{Field, Html};
use super::http::{Request, Response, decode_form};
use super::pages::{AUTH_DELAY, App, FORM_REFUSED, locked_message, new_password_problem, same_origin, start_session, value};
use super::session::{Digest, hex, random, same, sha256};
use crate::store::{Account, AccountId, Store, StoreError, Verified, check_login};

pub const VALID: Duration = Duration::from_secs(3600);
const DEAD: &str = "This setup link has expired or has already been used. Restart the server for a new link, or make an \
                    account admin on the server with <code>synology-mail-server account admin &lt;user name&gt; on</code>.";

pub struct Link {
    digest: Digest,
    created: Duration,
}

impl Link {
    /// A new link made at `now`, and its token: 128 random bits as 32 lowercase hex digits.
    pub fn new(now: Duration) -> (Link, String) {
        let token = hex(&random()[..16]);
        (Link { digest: sha256(token.as_bytes()), created: now }, token)
    }
}

fn reread(s: &Store, id: AccountId) -> Result<Account, StoreError> {
    s.account_by_id(id)?.ok_or_else(|| StoreError::NotFound(format!("account {id:?}")))
}

type Slot<'a> = MutexGuard<'a, Option<Link>>;

/// The link, held so no other setup request runs meanwhile, if `token` is its token and it
/// still works.
async fn live<'a>(app: &'a App, token: &str) -> Result<Option<Slot<'a>>, StoreError> {
    let mut slot = app.setup.lock().await;
    let Some(link) = &*slot else { return Ok(None) };
    if !same(&sha256(token.as_bytes()), &link.digest) {
        return Ok(None);
    }
    if app.clock.now().saturating_sub(link.created) >= VALID || app.blocking(|s| s.has_active_admin()).await? {
        *slot = None;
        return Ok(None);
    }
    Ok(Some(slot))
}

pub async fn open(app: &App, req: &Request) -> Result<Response, StoreError> {
    let token = req.query.strip_prefix("t=").unwrap_or_default();
    Ok(match live(app, token).await? {
        Some(_) => page(200, token, &Notes::default()),
        None => Response::error_because(404, DEAD),
    })
}

#[derive(Default)]
struct Notes<'a> {
    login: &'a str,
    message: Option<String>,
    new_login: &'a str,
    /// Errors of the new admin's user name, password and repeated password fields.
    errors: [Option<&'static str>; 3],
}

fn page(status: u16, token: &str, notes: &Notes<'_>) -> Response {
    let body = Html::page("Set up the first admin", None, None, |h| {
        let form = |h: &mut Html, what: &'static str| {
            h.raw("<form method=\"post\" action=\"/setup\"><input type=\"hidden\" name=\"t\" value=\"").text(token);
            h.raw("\"><input type=\"hidden\" name=\"do\" value=\"").raw(what).raw("\">");
        };
        h.raw("<p>No account can manage this server yet. This page works once, for an hour from the start of the server.</p>\n");
        h.raw("<h2>Make an existing account admin</h2>\n");
        if let Some(m) = &notes.message {
            h.raw("<p class=\"error\">").text(m).raw("</p>\n");
        }
        form(h, "promote");
        h.field(&Field { name: "login", label: "User name", kind: "text", autocomplete: "username", value: Some(notes.login), error: None });
        h.field(&Field { name: "password", label: "Its password", kind: "password", autocomplete: "current-password", value: None, error: None });
        h.raw("<button type=\"submit\">Make admin</button></form>\n<h2>Or create a new admin</h2>\n");
        form(h, "create");
        let [login, new, again] = notes.errors;
        h.field(&Field { name: "new_login", label: "User name", kind: "text", autocomplete: "off", value: Some(notes.new_login), error: login });
        h.field(&Field { name: "new", label: "Password (at least 12 characters)", kind: "password", autocomplete: "new-password", value: None, error: new });
        h.field(&Field { name: "again", label: "Password again", kind: "password", autocomplete: "new-password", value: None, error: again });
        h.raw("<button type=\"submit\">Create admin</button></form>\n");
    });
    Response::html(status, body)
}

pub async fn submit(app: &App, req: &Request, body: &[u8], ip: IpAddr) -> Result<Response, StoreError> {
    if !same_origin(req) {
        return Ok(Response::error_because(403, FORM_REFUSED));
    }
    let Some(form) = decode_form(body) else { return Ok(Response::error(400)) };
    let token = value(&form, "t");
    let Some(slot) = live(app, token).await? else { return Ok(Response::error_because(404, DEAD)) };
    match value(&form, "do") {
        "promote" => promote(app, req, &form, ip, slot).await,
        "create" => create(app, req, &form, ip, slot).await,
        _ => Ok(Response::error(400)),
    }
}

async fn promote(app: &App, req: &Request, form: &[(String, String)], ip: IpAddr, mut slot: Slot<'_>) -> Result<Response, StoreError> {
    let (token, login) = (value(form, "t"), value(form, "login"));
    let notes = |message: String| Notes { login, message: Some(message), ..Notes::default() };
    if let Some(left) = app.limiter.locked(ip, login, app.clock.now()) {
        return Ok(page(429, token, &notes(locked_message(left))));
    }
    let (who, password) = (login.to_string(), value(form, "password").to_string());
    let verified = app
        .checked(move |s| match s.verify_login(&who, &password)? {
            Verified::Valid(a) => {
                s.set_admin(&who, true)?;
                Ok(Verified::Valid(reread(s, a.id)?))
            }
            other => Ok(other),
        })
        .await?;
    match verified {
        Verified::Valid(account) => {
            *slot = None;
            app.limiter.succeeded(ip, login);
            crate::log_info!("web: {login:?} made admin with the setup link from {ip}");
            Ok(start_session(app, req, &account))
        }
        Verified::Disabled => {
            crate::log_info!("web: {login:?} refused admin with the setup link from {ip}: account disabled");
            Ok(page(403, token, &notes("Sign-in is blocked for this account. Create a new admin instead.".into())))
        }
        Verified::Invalid => {
            drop(slot);
            app.limiter.failed(ip, login, app.clock.now());
            crate::log_info!("web: {login:?} failed sign-in on the setup page from {ip}");
            app.clock.sleep(AUTH_DELAY).await;
            Ok(page(422, token, &notes("Wrong user name or password.".into())))
        }
    }
}

async fn create(app: &App, req: &Request, form: &[(String, String)], ip: IpAddr, mut slot: Slot<'_>) -> Result<Response, StoreError> {
    let (token, login, password) = (value(form, "t"), value(form, "new_login"), value(form, "new"));
    let mut notes = Notes { new_login: login, ..Notes::default() };
    if check_login(login).is_err() {
        notes.errors[0] = Some(LOGIN_RULES);
    }
    if let Some((field, error)) = new_password_problem(password, value(form, "again")) {
        notes.errors[field] = Some(error);
    }
    if notes.errors.iter().any(Option::is_some) {
        return Ok(page(422, token, &notes));
    }
    let (l, p) = (login.to_string(), password.to_string());
    let made = app
        .checked(move |s| {
            let id = s.create_account(&l, &p)?;
            s.set_admin(&l, true)?;
            reread(s, id)
        })
        .await;
    match made {
        Ok(account) => {
            *slot = None;
            crate::log_info!("web: {login:?} created as admin with the setup link from {ip}");
            Ok(start_session(app, req, &account))
        }
        Err(StoreError::AlreadyExists(_)) => {
            notes.errors[0] = Some("An account with this user name already exists. Make it admin with the form above.");
            Ok(page(409, token, &notes))
        }
        Err(e) => Err(e),
    }
}
