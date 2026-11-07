//! Admin pages: the account list with the new-account form, and each account's page with its
//! address, password, sign-in and admin forms. Accounts are named by id in URLs and forms. An admin cannot
//! block or demote their own account here, and the store keeps the last active admin.

use super::html::{Field, Html};
use super::http::{Request, Response};
use super::pages::{App, Me, admin_post, new_password_problem, see_other, signed_in_admin, value};
use crate::store::{Account, AccountId, StoreError, check_login, normalize_address};

const LAST_ADMIN: &str = "At least one admin must remain.";
const OWN_ACCESS: &str = "You cannot block your own sign-in or remove your own admin.";
const OWN_PASSWORD: &str = "Change your own password on your own page.";
pub(super) const LOGIN_RULES: &str = "Use 1 to 255 characters (fewer with accented or non-Latin letters), with no spaces or control characters.";
const ADDRESS_RULES: &str = "Use name@domain, or @domain for all other mail for a domain: one @, no spaces, no + before the @.";

type Form = Vec<(String, String)>;

fn param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|p| p.strip_prefix(name)?.strip_prefix('='))
}

fn date(unix: i64) -> String {
    let (y, m, d, ..) = crate::time::civil(unix);
    format!("{y:04}-{m:02}-{d:02}")
}

fn yes_no(on: bool) -> &'static str {
    if on { "Yes" } else { "No" }
}

fn hidden(h: &mut Html, name: &'static str, value: &str) {
    h.raw("<input type=\"hidden\" name=\"").raw(name).raw("\" value=\"").text(value).raw("\">");
}

/// The account named by an `id` value, if there is one.
async fn target(app: &App, id: Option<&str>) -> Result<Option<Account>, StoreError> {
    let Some(id) = id.and_then(|v| v.parse::<i64>().ok()) else { return Ok(None) };
    app.blocking(move |s| s.account_by_id(AccountId(id))).await
}

/// An admin's POST about the account in its `id` field. Err: the answer instead.
async fn action(app: &App, req: &Request, body: &[u8]) -> Result<Result<(Me, Form, Account), Response>, StoreError> {
    let (me, form) = match admin_post(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(Err(r)),
    };
    Ok(match target(app, Some(value(&form, "id"))).await? {
        Some(target) => Ok((me, form, target)),
        None => Err(Response::error(404)),
    })
}

/// Back to the account's page with a fixed code saying what was done.
fn done(id: AccountId, code: &'static str) -> Response {
    see_other(format!("/account?id={}&done={code}", id.0))
}

fn done_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "settings" => "Mailbox settings saved.",
        "created" => "The account has been added.",
        "password" => "The password has been set. The account's web sessions have ended.",
        "blocked" => "Sign-in is now blocked.",
        "allowed" => "Sign-in is allowed again.",
        "admin-on" => "The account is now an admin.",
        "admin-off" => "The account is no longer an admin.",
        "address-added" => "The address has been added.",
        "address-removed" => "The address has been removed.",
        _ => return None,
    })
}

// ---- the list and new accounts --------------------------------------------------------------

#[derive(Default)]
struct NewAccount<'a> {
    login: &'a str,
    /// Errors of the login, password and repeated password fields.
    errors: [Option<&'static str>; 3],
}

pub async fn list(app: &App, req: &Request) -> Result<Response, StoreError> {
    match signed_in_admin(app, req).await? {
        Ok(me) => list_page(app, &me, 200, NewAccount::default()).await,
        Err(r) => Ok(r),
    }
}

async fn list_page(app: &App, me: &Me, status: u16, new: NewAccount<'_>) -> Result<Response, StoreError> {
    let (accounts, addresses, settings) = app.blocking(|s| Ok((s.accounts()?, s.addresses()?, s.mailbox_overview()?))).await?;
    let body = Html::page("Accounts", Some(&me.session.csrf), Some("/accounts"), |h| {
        h.raw("<div class=\"table-wrap\"><table>\n<thead><tr><th>User name</th><th>Created</th><th>Admin</th><th>Sign-in blocked</th><th>Addresses</th><th>Storage used / quota</th><th>Forwarding</th></tr></thead>\n<tbody>");
        for a in &accounts {
            h.raw("<tr><td><a href=\"/account?id=").text(&a.id.0.to_string()).raw("\">").text(&a.login).raw("</a></td><td>");
            h.text(&date(a.created_at)).raw("</td><td>").raw(yes_no(a.admin)).raw("</td><td>").raw(yes_no(a.disabled)).raw("</td><td>");
            for (i, (addr, _)) in addresses.iter().filter(|(_, l)| *l == a.login).enumerate() {
                if i > 0 {
                    h.raw(", ");
                }
                h.address(addr);
            }
            h.raw("</td><td>");
            if let Some((used,quota,to,keep))=settings.get(&a.id) {
                h.text(&format!("{:.2} MiB / ",*used as f64/1048576.0));
                h.text(&if *quota==0 {"Unlimited".into()} else {format!("{} MiB",quota/1048576)}).raw("</td><td>");
                if let Some(to)=to { h.text(if *keep {"Copy to "} else {"Forward only to "}).text(to); } else { h.text("Off"); }
            } else { h.raw("—</td><td>—"); }
            h.raw("</td></tr>\n");
        }
        h.raw("</tbody></table></div>\n<h2>Add an account</h2>\n<form method=\"post\" action=\"/accounts\">").csrf(&me.session.csrf);
        let [login, password, again] = new.errors;
        h.field(&Field { name: "login", label: "User name", kind: "text", autocomplete: "off", value: Some(new.login), error: login });
        h.field(&Field { name: "password", label: "Password (at least 12 characters)", kind: "password", autocomplete: "new-password", value: None, error: password });
        h.field(&Field { name: "again", label: "Password again", kind: "password", autocomplete: "new-password", value: None, error: again });
        h.raw(r#"<label for="new_admin"><input id="new_admin" type="checkbox" name="new_admin" value="yes">Make this account an admin</label>"#);
        h.raw("<button type=\"submit\">Add account</button></form>\n");
    });
    Ok(Response::html(status, body))
}

pub async fn create(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (me, form) = match admin_post(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    let (login, password) = (value(&form, "login"), value(&form, "password"));
    let mut new = NewAccount { login, ..NewAccount::default() };
    if check_login(login).is_err() {
        new.errors[0] = Some(LOGIN_RULES);
    }
    if let Some((field, error)) = new_password_problem(password, value(&form, "again")) {
        new.errors[field] = Some(error);
    }
    if new.errors.iter().any(Option::is_some) {
        return list_page(app, &me, 422, new).await;
    }
    let (l, p) = (login.to_string(), password.to_string());
    let admin = value(&form,"new_admin")=="yes";
    match app.checked(move |s| s.create_account_with_role(&l, &p,admin)).await {
        Ok(id) => {
            crate::log_info!("web: {:?} added account {login:?}", me.account.login);
            Ok(done(id, "created"))
        }
        Err(StoreError::AlreadyExists(_)) => {
            new.errors[0] = Some("An account with this user name already exists.");
            list_page(app, &me, 409, new).await
        }
        Err(e) => Err(e),
    }
}

// ---- an account's page ----------------------------------------------------------------------

#[derive(Default)]
struct Notes {
    done: Option<&'static str>,
    message: Option<&'static str>,
    /// Errors of the new and repeated password fields.
    password: [Option<&'static str>; 2],
    /// The address typed into the add form, and its error.
    address: String,
    address_error: Option<String>,
}

pub async fn account(app: &App, req: &Request) -> Result<Response, StoreError> {
    let me = match signed_in_admin(app, req).await? {
        Ok(me) => me,
        Err(r) => return Ok(r),
    };
    let Some(target) = target(app, param(&req.query, "id")).await? else { return Ok(Response::error(404)) };
    let done = param(&req.query, "done").and_then(done_message);
    account_page(app, &me, &target, 200, Notes { done, ..Notes::default() }).await
}

async fn account_page(app: &App, me: &Me, target: &Account, status: u16, notes: Notes) -> Result<Response, StoreError> {
    let login = target.login.clone();
    let mut addresses = app.blocking(|s| s.addresses()).await?;
    addresses.retain(|(_, l)| *l == login);
    let (id, own, csrf) = (target.id.0.to_string(), target.id == me.account.id, &me.session.csrf);
    let target_id = target.id;
    let (used,quota,forward) = app.blocking(move |s|s.mailbox_settings(target_id)).await?;
    let keep = app.blocking(move|s|s.keeps_copy(target_id)).await?;
    let destinations = crate::store::preferences::verified_destinations();
    let body = Html::page("Account", Some(csrf), Some("/account"), |h| {
        if let Some(m) = notes.done {
            h.raw("<p class=\"notice\">").raw(m).raw("</p>\n");
        }
        if let Some(m) = notes.message {
            h.raw("<p class=\"error\">").raw(m).raw("</p>\n");
        }
        h.raw("<h2>").text(&login).raw("</h2>\n<ul><li>Created: ").text(&date(target.created_at));
        h.raw("</li><li>Admin: ").raw(yes_no(target.admin)).raw("</li><li>Sign-in blocked: ").raw(yes_no(target.disabled)).raw("</li></ul>\n");
        if target.disabled {
            h.raw("<p class=\"notice\">Sign-in is blocked for this account. Its mail still arrives, and mail apps already connected stay connected until they disconnect.</p>\n");
        }

        h.raw(r#"<h2>Mailbox settings</h2><form method="post" action="/account/settings">"#).csrf(csrf);
        hidden(h, "id", &id);
        h.raw(r#"<label for="quota">Storage limit (MiB)</label><input id="quota" name="quota" type="number" min="0" step="1" value=""#);
        if quota > 0 { h.text(&(quota / 1048576).to_string()); }
        h.raw("\"><p>").text(&format!("{:.2} MiB used. Default 1024 MiB (1 GiB). Leave blank for unlimited.", used as f64 / 1048576.0))
            .raw(r#"</p><label for="forward">Forward to</label>"#);
        if crate::store::preferences::external_relay() {
            h.raw(r#"<input type="email" name="forward" id="forward" value=""#).text(forward.as_deref().unwrap_or("")).raw("\">");
        } else {
        h.raw(r#"<select id="forward" name="forward"><option value="">Off</option>"#);
        for dest in &destinations {
            h.raw(r#"<option value=""#).text(dest).raw("\"");
            if forward.as_ref() == Some(dest) { h.raw(" selected"); }
            h.raw(">").text(dest).raw("</option>");
        }
        h.raw("</select>");
        }
        h.raw(r#"<label for="delivery">When forwarding</label><select id="delivery" name="delivery"><option value="copy""#);
        if keep {h.raw(" selected");}
        h.raw(r#">Keep a copy in this inbox</option><option value="only""#);
        if !keep {h.raw(" selected");}
        h.raw(">Forward only</option></select><button>Save mailbox settings</button></form>");
        h.raw("<h2>Addresses</h2>\n");
        if addresses.is_empty() {
            h.raw("<p>No addresses deliver to this account.</p>\n");
        } else {
            h.raw("<ul>");
            for (a, _) in &addresses {
                h.raw("<li>").address(a).raw(" <form method=\"post\" action=\"/account/address/remove\">").csrf(csrf);
                hidden(h, "id", &id);
                hidden(h, "address", a);
                h.raw("<button type=\"submit\" class=\"secondary\">Remove<span class=\"visually-hidden\"> ").text(a).raw("</span></button></form></li>");
            }
            h.raw("</ul>\n");
        }
        h.raw("<form method=\"post\" action=\"/account/address/add\">").csrf(csrf);
        hidden(h, "id", &id);
        let label = "Add an address: name@domain, or @domain for all other mail for that domain";
        h.field(&Field { name: "address", label, kind: "text", autocomplete: "off", value: Some(&notes.address), error: notes.address_error.as_deref() });
        h.raw("<button type=\"submit\">Add address</button></form>\n");

        h.raw("<h2>Password</h2>\n");
        if own {
            h.raw("<p>Change your own password on <a href=\"/me\">your page</a>.</p>\n");
        } else {
            let [new, again] = notes.password;
            h.raw("<form method=\"post\" action=\"/account/password\">").csrf(csrf);
            hidden(h, "id", &id);
            h.field(&Field { name: "password", label: "New password (at least 12 characters)", kind: "password", autocomplete: "new-password", value: None, error: new });
            h.field(&Field { name: "again", label: "New password again", kind: "password", autocomplete: "new-password", value: None, error: again });
            h.raw("<button type=\"submit\">Set password</button></form>\n");
        }

        h.raw("<h2>Access</h2>\n");
        if own {
            h.raw("<p>Another admin can block your sign-in or remove your admin.</p>\n");
        } else {
            let (action, button) = if target.disabled { ("/account/enable", "Allow sign-in") } else { ("/account/disable", "Block sign-in") };
            h.raw("<form method=\"post\" action=\"").raw(action).raw("\">").csrf(csrf);
            hidden(h, "id", &id);
            h.raw("<button type=\"submit\" class=\"secondary\">").raw(button).raw("</button></form>\n");
            h.raw("<form method=\"post\" action=\"/account/admin\">").csrf(csrf);
            hidden(h, "id", &id);
            hidden(h, "admin", if target.admin { "off" } else { "on" });
            h.raw("<button type=\"submit\" class=\"secondary\">").raw(if target.admin { "Remove admin" } else { "Make admin" }).raw("</button></form>\n");
        }
    });
    Ok(Response::html(status, body))
}

pub async fn set_password(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (me, form, target) = match action(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    if target.id == me.account.id {
        return account_page(app, &me, &target, 409, Notes { message: Some(OWN_PASSWORD), ..Notes::default() }).await;
    }
    let password = value(&form, "password").to_string();
    if let Some((field, error)) = new_password_problem(&password, value(&form, "again")) {
        let mut notes = Notes::default();
        notes.password[field - 1] = Some(error);
        return account_page(app, &me, &target, 422, notes).await;
    }
    let login = target.login.clone();
    app.checked(move |s| s.set_password(&login, &password)).await?;
    crate::log_info!("web: {:?} set the password of {:?}", me.account.login, target.login);
    Ok(done(target.id, "password"))
}

/// Block or allow sign-in, or make or remove admin.
pub async fn set_flag(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (me, form, target) = match action(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    // (sets admin rather than disabled, on, code, what the log says)
    let (admin, on, code, did) = match (req.path.as_str(), value(&form, "admin")) {
        ("/account/disable", _) => (false, true, "blocked", "blocked sign-in of"),
        ("/account/enable", _) => (false, false, "allowed", "allowed sign-in of"),
        (_, "on") => (true, true, "admin-on", "made admin"),
        (_, "off") => (true, false, "admin-off", "removed admin from"),
        _ => return Ok(Response::error(400)),
    };
    if target.id == me.account.id && admin != on {
        let me_id = me.account.id;
        let others = app.blocking(move |s| Ok(s.accounts()?.iter().any(|a| a.admin && !a.disabled && a.id != me_id))).await?;
        let message = if others { OWN_ACCESS } else { LAST_ADMIN };
        return account_page(app, &me, &target, 409, Notes { message: Some(message), ..Notes::default() }).await;
    }
    let login = target.login.clone();
    match app.blocking(move |s| if admin { s.set_admin(&login, on) } else { s.set_disabled(&login, on) }).await {
        Ok(()) => {
            crate::log_info!("web: {:?} {did} {:?}", me.account.login, target.login);
            Ok(done(target.id, code))
        }
        Err(StoreError::LastAdmin) => account_page(app, &me, &target, 409, Notes { message: Some(LAST_ADMIN), ..Notes::default() }).await,
        Err(e) => Err(e),
    }
}

pub async fn add_address(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (me, form, target) = match action(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    let typed = value(&form, "address");
    let refused = |error: String| Notes { address: typed.to_string(), address_error: Some(error), ..Notes::default() };
    let Ok(address) = normalize_address(typed) else {
        return account_page(app, &me, &target, 422, refused(ADDRESS_RULES.to_string())).await;
    };
    let (a, login) = (address.clone(), target.login.clone());
    match app.blocking(move |s| s.add_address(&a, &login)).await {
        Ok(()) => {
            crate::log_info!("web: {:?} added address {address:?} to {:?}", me.account.login, target.login);
            Ok(done(target.id, "address-added"))
        }
        Err(StoreError::AlreadyExists(_)) => {
            let a = address.clone();
            let owner = app.blocking(move |s| Ok(s.addresses()?.into_iter().find(|(x, _)| *x == a).map(|(_, l)| l))).await?;
            let error = match owner {
                Some(owner) => format!("{address} already delivers to {owner}."),
                None => format!("{address} is already in use."),
            };
            account_page(app, &me, &target, 409, refused(error)).await
        }
        Err(e) => Err(e),
    }
}

pub async fn remove_address(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (me, form, target) = match action(app, req, body).await? {
        Ok(ok) => ok,
        Err(r) => return Ok(r),
    };
    let (address, login) = (value(&form, "address").to_string(), target.login.clone());
    let a = address.clone();
    let removed = app
        .blocking(move |s| {
            let owned = s.addresses()?.iter().any(|(x, l)| *x == a && *l == login);
            if owned {
                s.remove_address(&a)?;
            }
            Ok(owned)
        })
        .await?;
    if !removed {
        return Ok(Response::error(404));
    }
    crate::log_info!("web: {:?} removed address {address:?} from {:?}", me.account.login, target.login);
    Ok(done(target.id, "address-removed"))
}

pub async fn settings(app: &App, req: &Request, body: &[u8]) -> Result<Response, StoreError> {
    let (_, form, target) = match action(app, req, body).await? {Ok(v)=>v,Err(r)=>return Ok(r)};
    if !form.iter().any(|(k,_)| k=="quota") || !form.iter().any(|(k,_)| k=="forward") {return Ok(Response::error(400));}
    let mib = value(&form, "quota").trim();
    let quota = if mib.is_empty() {Some(0)} else {mib.parse::<i64>().ok().filter(|n|*n>=0).and_then(|n|n.checked_mul(1048576))};
    let Some(quota) = quota else {return Ok(Response::error_because(422,"Enter a whole number of MiB or leave the limit blank."));};
    let to = value(&form,"forward").to_owned();
    let id = target.id;
    let keep = match value(&form,"delivery") {""|"copy"=>true,"only"=>false,_=>return Ok(Response::error(422))};
    match app.blocking(move |s| s.set_forwarding(id,quota,(!to.is_empty()).then_some(to.as_str()),keep)).await {
        Ok(())=>Ok(done(id,"settings")),
        Err(StoreError::InvalidInput(_))=>Ok(Response::error_because(422,"Choose a verified external address.")),
        Err(e)=>Err(e),
    }
}
