//! The pages: sign in, sign out, and the own page with its password form; `admin` has the account
//! pages. Every POST must come from this site's own origin; a signed-in POST also needs a live
//! session, then the session's CSRF token, in that order. Admin pages then need the account to be
//! an admin, as read from the store on this request.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore};

use super::{admin, setup};
use super::html::{Field, Html};
use super::http::{Method, Request, Response, decode_form};
use super::session::{COOKIE, Limiter, Session, Sessions, same};
use crate::inbound::Clock;
use crate::store::{Account, Store, StoreError, Verified, check_password};

const NOT_ADMIN: &str = "Only admins can open this page.";
pub(super) const FORM_REFUSED: &str = "The form did not come from this site's own page, or the page was too old. Reload the page and try again.";

/// How long a failed password check waits before it answers.
pub(super) const AUTH_DELAY: Duration = Duration::from_secs(2);
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

pub struct App {
    pub(super) store: Arc<Store>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) sessions: Sessions,
    pub(super) limiter: Limiter,
    /// Password checks waiting here do not hold a blocking thread.
    checks: Semaphore,
    pub(super) setup: Mutex<Option<setup::Link>>,
}

impl App {
    pub fn new(store: Arc<Store>, clock: Arc<dyn Clock>, setup: Option<setup::Link>) -> App {
        App { store, clock, sessions: Sessions::default(), limiter: Limiter::default(), checks: Semaphore::new(2), setup: Mutex::new(setup) }
    }

    pub(super) async fn blocking<T: Send + 'static>(&self, f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static) -> Result<T, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&store)).await.unwrap_or_else(|e| Err(StoreError::Io(io::Error::other(e.to_string()))))
    }

    /// `blocking` for work that hashes or verifies a password.
    pub(super) async fn checked<T: Send + 'static>(&self, f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static) -> Result<T, StoreError> {
        let _permit = self.checks.acquire().await.ok();
        self.blocking(f).await
    }
}

/// Where a signed-in account starts.
fn home(account: &Account) -> &'static str {
    if account.admin { "/accounts" } else { "/me" }
}

pub async fn handle(app: &App, req: &Request, body: &[u8], ip: IpAddr) -> Response {
    let get = matches!(req.method, Method::Get | Method::Head);
    let answer = match (get, req.path.as_str()) {
        (true, "/login") => Ok(login_page(200, "", None)),
        (false, "/login") => sign_in(app, req, body, ip).await,
        (true, "/") => signed_in(app, req).await.map(|me| see_other(me.map_or("/login", |me| home(&me.account)))),
        (_, "/compose") => super::compose::handle(app, req, body).await,
        (true, "/inbox" | "/message" | "/outbox") => super::inbox::open(app, req).await,
        (true, "/me") => match signed_in(app, req).await {
            Ok(Some(me)) => own_page(app, &me, 200, Notes { done: req.query == "done=password", ..Notes::default() }).await,
            other => other.map(|_| see_other("/login")),
        },
        (false, "/logout") => sign_out(app, req, body).await,
        (false, "/me/password") => change_password(app, req, body, ip).await,
        (true, "/accounts") => admin::list(app, req).await,
        (false, "/accounts") => admin::create(app, req, body).await,
        (true, "/account") => admin::account(app, req).await,
        (false, "/account/settings") => admin::settings(app, req, body).await,
        (false, "/account/password") => admin::set_password(app, req, body).await,
        (false, "/account/disable" | "/account/enable" | "/account/admin") => admin::set_flag(app, req, body).await,
        (false, "/account/address/add") => admin::add_address(app, req, body).await,
        (false, "/account/address/remove") => admin::remove_address(app, req, body).await,
        (true, "/setup") => setup::open(app, req).await,
        (false, "/setup") => setup::submit(app, req, body, ip).await,
        _ => Ok(Response::error(404)),
    };
    answer.unwrap_or_else(|e| {
        crate::log_error!("web: {e:?}");
        Response::error(500)
    })
}

pub(super) fn see_other(to: impl Into<String>) -> Response {
    Response { headers: vec![("Location", to.into())], ..Response::html(303, Vec::new()) }
}

pub(super) fn same_origin(req: &Request) -> bool {
    !req.host.is_empty() && req.origin.as_deref().and_then(|o| o.strip_prefix("https://")) == Some(req.host.as_str())
}

pub(super) fn value<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    form.iter().find(|(k, _)| k == name).map_or("", |(_, v)| v.as_str())
}

pub(super) fn locked_message(left: Duration) -> String {
    let m = left.as_secs().div_ceil(60).max(1);
    format!("Too many attempts, try again in {m} minute{}.", if m == 1 { "" } else { "s" })
}

// ---- signing in and out ---------------------------------------------------------------------

fn login_page(status: u16, login: &str, message: Option<&str>) -> Response {
    Response::html(
        status,
        Html::page("Sign in", None, None, |h| {
            if let Some(m) = message {
                h.raw("<p class=\"error\">").text(m).raw("</p>\n");
            }
            h.raw("<form method=\"post\" action=\"/login\">");
            h.field(&Field { name: "login", label: "User name", kind: "text", autocomplete: "username", value: Some(login), error: None });
            h.field(&Field { name: "password", label: "Password", kind: "password", autocomplete: "current-password", value: None, error: None });
            h.raw("<button type=\"submit\">Sign in</button></form>\n");
        }),
    )
}

async fn sign_in(app: &App, req: &Request, body: &[u8], ip: IpAddr) -> Result<Response, StoreError> {
    if !same_origin(req) {
        return Ok(Response::error_because(403, FORM_REFUSED));
    }
    let Some(form) = decode_form(body) else { return Ok(Response::error(400)) };
    let (login, password) = (value(&form, "login").to_string(), value(&form, "password").to_string());
    if let Some(left) = app.limiter.locked(ip, &login, app.clock.now()) {
        return Ok(login_page(429, &login, Some(&locked_message(left))));
    }
    let who = login.clone();
    match app.checked(move |s| s.verify_login(&who, &password)).await? {
        Verified::Valid(account) => {
            app.limiter.succeeded(ip, &login);
            crate::log_info!("web: {login:?} signed in from {ip}");
            Ok(start_session(app, req, &account))
        }
        Verified::Disabled => {
            crate::log_info!("web: {login:?} refused sign-in from {ip}: account disabled");
            Ok(login_page(403, &login, Some("Sign-in is blocked for this account. Ask your admin to allow sign-in again.")))
        }
        Verified::Invalid => {
            app.limiter.failed(ip, &login, app.clock.now());
            crate::log_info!("web: {login:?} failed sign-in from {ip}");
            app.clock.sleep(AUTH_DELAY).await;
            Ok(login_page(422, &login, Some("Wrong user name or password.")))
        }
    }
}

/// A new session for `account` (ending the request's old one), sent to its start page.
pub(super) fn start_session(app: &App, req: &Request, account: &Account) -> Response {
    if let Some(old) = req.cookie(COOKIE) {
        app.sessions.remove(old);
    }
    let id = app.sessions.create(account.id, account.auth_stamp, app.clock.now());
    let mut r = see_other(home(account));
    r.headers.push(("Set-Cookie", format!("{COOKIE}={id}; Path=/; Secure; HttpOnly; SameSite=Strict")));
    r
}

pub(super) struct Me {
    pub(super) cookie: String,
    pub(super) session: Session,
    pub(super) account: Account,
}

/// The request's live session with its account, re-read on every request: a disabled account or
/// a password changed since sign-in ends the session.
pub(super) async fn signed_in(app: &App, req: &Request) -> Result<Option<Me>, StoreError> {
    let Some(cookie) = req.cookie(COOKIE) else { return Ok(None) };
    let Some(session) = app.sessions.get(cookie, app.clock.now()) else { return Ok(None) };
    let id = session.account;
    match app.blocking(move |s| s.account_by_id(id)).await? {
        Some(account) if !account.disabled && account.auth_stamp == session.stamp => Ok(Some(Me { cookie: cookie.to_string(), session, account })),
        _ => {
            app.sessions.remove(cookie);
            Ok(None)
        }
    }
}

/// The signed-in admin. Err: the answer instead (to sign in, or 403 for an account that is not
/// an admin).
pub(super) async fn signed_in_admin(app: &App, req: &Request) -> Result<Result<Me, Response>, StoreError> {
    Ok(match signed_in(app, req).await? {
        Some(me) if me.account.admin => Ok(me),
        Some(_) => Err(Response::error_because(403, NOT_ADMIN)),
        None => Err(see_other("/login")),
    })
}

/// `signed_in_post`, then the account must be an admin.
pub(super) async fn admin_post(app: &App, req: &Request, body: &[u8]) -> Result<Result<(Me, Vec<(String, String)>), Response>, StoreError> {
    Ok(match signed_in_post(app, req, body).await? {
        Ok((me, _)) if !me.account.admin => Err(Response::error_because(403, NOT_ADMIN)),
        other => other,
    })
}

/// Origin, then session, then CSRF token. Err: the answer instead.
pub(super) async fn signed_in_post(app: &App, req: &Request, body: &[u8]) -> Result<Result<(Me, Vec<(String, String)>), Response>, StoreError> {
    if !same_origin(req) {
        return Ok(Err(Response::error_because(403, FORM_REFUSED)));
    }
    let Some(me) = signed_in(app, req).await? else { return Ok(Err(see_other("/login"))) };
    let Some(form) = decode_form(body) else { return Ok(Err(Response::error(400))) };
    if !form.iter().find(|(k, _)| k == "csrf").is_some_and(|(_, t)| same(t.as_bytes(), me.session.csrf.as_bytes())) {
        return Ok(Err(Response::error_because(403, FORM_REFUSED)));
    }
    Ok(Ok((me, form)))
}

async fn sign_out(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let me = match signed_in_post(app, req, body).await? {
        Ok((me, _)) => me,
        Err(r) => return Ok(r),
    };
    app.sessions.remove(&me.cookie);
    crate::log_info!("web: {:?} signed out", me.account.login);
    let mut r = see_other("/login");
    r.headers.push(("Set-Cookie", format!("{COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")));
    Ok(r)
}

// ---- the own page ---------------------------------------------------------------------------

#[derive(Default)]
struct Notes {
    done: bool,
    message: Option<String>,
    /// Errors of the current, new and repeated password fields.
    errors: [Option<&'static str>; 3],
}

async fn own_page(app: &App, me: &Me, status: u16, notes: Notes) -> Result<Response, StoreError> {
    let login = me.account.login.clone();
    let mut addresses = app.blocking(|s| s.addresses()).await?;
    addresses.retain(|(_, l)| *l == login);
    let body = Html::page("Your account", Some(&me.session.csrf), me.account.admin.then_some("/me"), |h| {
        h.raw("<p><a href=\"/inbox\">Open your inbox</a></p>");
        if notes.done {
            h.raw("<p class=\"notice\">Your password has been changed.</p>\n");
        }
        if let Some(m) = &notes.message {
            h.raw("<p class=\"error\">").text(m).raw("</p>\n");
        }
        h.raw("<p>Signed in as <strong>").text(&login).raw("</strong>.</p>\n<h2>Addresses</h2>\n");
        if addresses.is_empty() {
            h.raw("<p>No addresses deliver to this account.</p>\n");
        } else {
            h.raw("<ul>");
            for (address, _) in &addresses {
                h.raw("<li>").address(address).raw("</li>");
            }
            h.raw("</ul>\n");
        }
        let [current, new, again] = notes.errors;
        h.raw("<h2>Change password</h2>\n<form method=\"post\" action=\"/me/password\">").csrf(&me.session.csrf);
        let password = |name, label, autocomplete, error| Field { name, label, kind: "password", autocomplete, value: None, error };
        h.field(&password("current", "Current password", "current-password", current));
        h.field(&password("new", "New password (at least 12 characters)", "new-password", new));
        h.field(&password("again", "New password again", "new-password", again));
        h.raw("<button type=\"submit\">Change password</button></form>\n");
    });
    Ok(Response::html(status, body))
}

/// The web's rules for a new password (the CLI's, plus a length range); the error for the field.
pub(super) fn new_password_problem(new: &str, again: &str) -> Option<(usize, &'static str)> {
    if new.chars().count() < MIN_PASSWORD_CHARS {
        Some((1, "Use at least 12 characters."))
    } else if new.len() > MAX_PASSWORD_BYTES {
        Some((1, "Use at most 1,024 characters (fewer with accented or non-Latin letters)."))
    } else if check_password(new).is_err() {
        Some((1, "A password cannot contain line breaks."))
    } else if new != again {
        Some((2, "The two new passwords differ."))
    } else {
        None
    }
}

async fn change_password(app: &App, req: &Request, body: &[u8], ip: IpAddr) -> Result<Response, StoreError> {
    let (me, form) = match signed_in_post(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    let login = me.account.login.clone();
    if let Some(left) = app.limiter.locked(ip, &login, app.clock.now()) {
        return own_page(app, &me, 429, Notes { message: Some(locked_message(left)), ..Notes::default() }).await;
    }
    let (current, new) = (value(&form, "current").to_string(), value(&form, "new").to_string());
    let problem = match current.is_empty() {
        true => Some((0, "Enter your current password.")),
        false => new_password_problem(&new, value(&form, "again")),
    };
    if let Some((field, error)) = problem {
        let mut notes = Notes::default();
        notes.errors[field] = Some(error);
        return own_page(app, &me, 422, notes).await;
    }

    let (who, id) = (login.clone(), me.account.id);
    let stamp = app
        .checked(move |s| match s.verify_login(&who, &current)? {
            Verified::Valid(a) if a.id == id => {
                s.set_password(&who, &new)?;
                let a = s.account_by_id(id)?.ok_or_else(|| StoreError::NotFound(format!("account {who}")))?;
                Ok(Some(a.auth_stamp))
            }
            _ => Ok(None),
        })
        .await?;
    match stamp {
        Some(stamp) => {
            app.sessions.renew(&me.cookie, stamp);
            app.limiter.succeeded(ip, &login);
            crate::log_info!("web: {login:?} changed own password");
            Ok(see_other("/me?done=password"))
        }
        None => {
            app.limiter.failed(ip, &login, app.clock.now());
            crate::log_info!("web: {login:?} gave a wrong current password from {ip}");
            app.clock.sleep(AUTH_DELAY).await;
            let mut notes = Notes::default();
            notes.errors[0] = Some("Wrong password.");
            own_page(app, &me, 422, notes).await
        }
    }
}
