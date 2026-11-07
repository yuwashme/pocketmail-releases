//! Accounts, argon2id passwords, addresses and recipient routing.

use std::sync::{Condvar, Mutex};

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{AccountId, Store, StoreError, is_constraint, lock, now_unix};

const ACCOUNT_COLS: &str = "id, login, created_at, disabled, admin, auth_stamp";

/// argon2id m=12 MiB, t=3, p=1.
const M_COST_KIB: u32 = 12 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Clone, Debug)]
pub struct Account {
    pub id: AccountId,
    pub login: String,
    pub created_at: i64,
    pub disabled: bool,
    pub admin: bool,
    /// Random, non-zero once a password has been set through the store; new at every change.
    pub auth_stamp: i64,
}

/// The outcome of `Store::verify_login`.
#[derive(Debug)]
pub enum Verified {
    Valid(Account),
    /// The right password for a disabled account.
    Disabled,
    /// A wrong password or an unknown login.
    Invalid,
}

fn account_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: AccountId(r.get(0)?),
        login: r.get(1)?,
        created_at: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
        disabled: r.get::<_, Option<bool>>(3)?.unwrap_or(false),
        admin: r.get(4)?,
        auth_stamp: r.get(5)?,
    })
}

fn new_auth_stamp() -> Result<i64, StoreError> {
    loop {
        let s = getrandom::u64().map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))? as i64;
        if s != 0 {
            return Ok(s);
        }
    }
}

fn hasher() -> Argon2<'static> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_password(password: &str) -> Result<String, StoreError> {
    let h: PasswordHash = hasher().hash_password(password.as_bytes()).map_err(|e| StoreError::Hash(e.to_string()))?;
    Ok(h.to_string())
}

/// Verify against a PHC string; the string's own params are used. A malformed hash never matches.
fn verify(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => hasher().verify_password(password.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

// Syntactically valid, fixed-cost PHC for missing accounts. The result is always discarded.
const DUMMY_PHC: &str = "$argon2id$v=19$m=12288,t=3,p=1$bm8tc3VjaC1tYWlsYm94IQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Counting semaphore: at most `max` argon2 hashes or verifies (12 MiB each) at once.
pub(crate) struct Gate {
    busy: Mutex<usize>,
    freed: Condvar,
    max: usize,
}

pub(crate) struct Permit<'a>(&'a Gate);

impl Gate {
    pub(crate) fn new(max: usize) -> Gate {
        Gate { busy: Mutex::new(0), freed: Condvar::new(), max }
    }

    fn acquire(&self) -> Permit<'_> {
        let mut busy = lock(&self.busy);
        while *busy >= self.max {
            busy = self.freed.wait(busy).unwrap_or_else(|e| e.into_inner());
        }
        *busy += 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *lock(&self.0.busy) -= 1;
        self.0.freed.notify_one();
    }
}

pub fn check_login(login: &str) -> Result<(), StoreError> {
    if login.is_empty() || login.len() > 255 {
        return Err(StoreError::InvalidInput("login must be 1-255 bytes".into()));
    }
    if login.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(StoreError::InvalidInput("login must not contain spaces or control characters".into()));
    }
    Ok(())
}

pub fn check_password(password: &str) -> Result<(), StoreError> {
    if password.is_empty() {
        return Err(StoreError::InvalidInput("password must not be empty".into()));
    }
    // NUL separates AUTH PLAIN fields and CR/LF ends an IMAP line: such a password could never log in.
    if password.contains(['\0', '\r', '\n']) {
        return Err(StoreError::InvalidInput("password must not contain NUL, CR or LF".into()));
    }
    Ok(())
}

/// Lowercased "local@domain" or "@domain" for registration. Rejects a '+' in the local part
/// (it would never be reached: routing strips "+tag"), more than one '@', spaces and control chars.
pub fn normalize_address(address: &str) -> Result<String, StoreError> {
    let a = address.to_lowercase();
    let Some((local, domain)) = a.split_once('@') else {
        return Err(StoreError::InvalidInput(format!("{address:?} has no '@'")));
    };
    if domain.is_empty() || domain.contains('@') {
        return Err(StoreError::InvalidInput(format!("{address:?} needs exactly one '@' and a domain")));
    }
    if local.contains('+') {
        return Err(StoreError::InvalidInput(format!("{address:?}: '+' in the local part is reserved for tags")));
    }
    if a.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(StoreError::InvalidInput(format!("{address:?} contains spaces or control characters")));
    }
    Ok(a)
}

impl Store {
    /// Also creates the account's INBOX (uidvalidity = creation unix seconds).
    pub fn create_account(&self, login: &str, password: &str) -> Result<AccountId, StoreError> {
        self.create_account_with_role(login,password,false)
    }

    pub fn create_account_with_role(&self, login:&str, password:&str, admin:bool)->Result<AccountId,StoreError>{
        check_login(login)?;
        check_password(password)?;
        if self.account_id(login)?.is_some() {
            return Err(StoreError::AlreadyExists(format!("account {login}")));
        }
        let hash = self.hash(password)?; // slow: outside the writer lock
        let stamp = new_auth_stamp()?;
        let now = now_unix();
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match tx.execute(
            "INSERT INTO accounts(login, password_hash, created_at, disabled, auth_stamp, admin) VALUES (?, ?, ?, 0, ?, ?)",
            params![login, hash, now, stamp,admin],
        ) {
            Err(e) if is_constraint(&e) => return Err(StoreError::AlreadyExists(format!("account {login}"))),
            r => r?,
        };
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO mailboxes(account_id, name, uidvalidity) VALUES (?, 'INBOX', ?)", params![id, now])?;
        tx.commit()?;
        Ok(AccountId(id))
    }

    /// Also gives the account a new `auth_stamp`, even when the password is the same.
    pub fn set_password(&self, login: &str, password: &str) -> Result<(), StoreError> {
        check_password(password)?;
        if self.account_id(login)?.is_none() {
            return Err(StoreError::NotFound(format!("account {login}")));
        }
        let hash = self.hash(password)?;
        let stamp = new_auth_stamp()?;
        let n = self
            .writer()
            .execute("UPDATE accounts SET password_hash = ?, auth_stamp = ? WHERE login = ?", params![hash, stamp, login])?;
        if n == 0 {
            return Err(StoreError::NotFound(format!("account {login}")));
        }
        Ok(())
    }

    fn hash(&self, password: &str) -> Result<String, StoreError> {
        let _permit = self.argon2_gate.acquire();
        hash_password(password)
    }

    pub fn accounts(&self) -> Result<Vec<Account>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(&format!("SELECT {ACCOUNT_COLS} FROM accounts ORDER BY id"))?;
        let rows = st.query_map([], account_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn account_by_id(&self, id: AccountId) -> Result<Option<Account>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?"))?;
        Ok(st.query_row([id.0], account_row).optional()?)
    }

    /// Refused with `LastAdmin` when it would demote the last enabled admin.
    pub fn set_admin(&self, login: &str, on: bool) -> Result<(), StoreError> {
        self.set_flag(login, "admin", on, !on)
    }

    /// A disabled account cannot log in; its mail still arrives. Refused with `LastAdmin` when it
    /// would disable the last enabled admin.
    pub fn set_disabled(&self, login: &str, on: bool) -> Result<(), StoreError> {
        self.set_flag(login, "disabled", on, on)
    }

    /// Is any account both admin and enabled?
    pub fn has_active_admin(&self) -> Result<bool, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT 1 FROM accounts WHERE admin = 1 AND IFNULL(disabled, 0) = 0")?;
        Ok(st.exists([])?)
    }

    /// Set `column` (admin or disabled). With `guard`, refuse if the account is an active admin
    /// and no other is; checked inside the write transaction so two such changes cannot both pass.
    fn set_flag(&self, login: &str, column: &str, on: bool, guard: bool) -> Result<(), StoreError> {
        let mut c = self.writer();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active_admin: Option<bool> = tx
            .query_row("SELECT admin = 1 AND IFNULL(disabled, 0) = 0 FROM accounts WHERE login = ?", [login], |r| r.get(0))
            .optional()?;
        let Some(active_admin) = active_admin else {
            return Err(StoreError::NotFound(format!("account {login}")));
        };
        if guard && active_admin {
            let others: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE admin = 1 AND IFNULL(disabled, 0) = 0 AND login <> ?)",
                [login],
                |r| r.get(0),
            )?;
            if !others {
                return Err(StoreError::LastAdmin);
            }
        }
        tx.execute(&format!("UPDATE accounts SET {column} = ? WHERE login = ?"), params![on, login])?;
        tx.commit()?;
        Ok(())
    }

    pub fn account_id(&self, login: &str) -> Result<Option<AccountId>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT id FROM accounts WHERE login = ?")?;
        Ok(st.query_row([login], |r| r.get(0)).optional()?.map(AccountId))
    }

    /// Ok(None) for a wrong password, an unknown login or a disabled account; an unknown login
    /// still runs one (dummy) argon2 verify so both take the same time. At most two verifies run
    /// at once (12 MiB each).
    pub fn authenticate(&self, login: &str, password: &str) -> Result<Option<AccountId>, StoreError> {
        Ok(match self.verify_login(login, password)? {
            Verified::Valid(account) => Some(account.id),
            Verified::Disabled | Verified::Invalid => None,
        })
    }

    /// `authenticate` that also tells a disabled account with the right password apart, so the
    /// web can say why. A disabled account with a wrong password is `Invalid`.
    pub fn verify_login(&self, login: &str, password: &str) -> Result<Verified, StoreError> {
        let row: Option<(Account, String)> = {
            let c = self.reader();
            let mut st = c.prepare_cached(&format!("SELECT {ACCOUNT_COLS}, password_hash FROM accounts WHERE login = ?"))?;
            st.query_row([login], |r| Ok((account_row(r)?, r.get(6)?))).optional()?
        };
        let _permit = self.argon2_gate.acquire();
        Ok(match row {
            Some((_, hash)) if !verify(password, &hash) => Verified::Invalid,
            Some((account, _)) if account.disabled => Verified::Disabled,
            Some((account, _)) => Verified::Valid(account),
            None => {
                verify(password, DUMMY_PHC);
                Verified::Invalid
            }
        })
    }

    // ---- addresses and routing -------------------------------------------------------------

    /// Register "user@dom" or the catch-all "@dom" (stored lowercase) for an account.
    pub fn add_address(&self, address: &str, login: &str) -> Result<(), StoreError> {
        let a = normalize_address(address)?;
        let id = self.account_id(login)?.ok_or_else(|| StoreError::NotFound(format!("account {login}")))?;
        match self.writer().execute("INSERT INTO addresses(address, account_id) VALUES (?, ?)", params![a, id.0]) {
            Err(e) if is_constraint(&e) => Err(StoreError::AlreadyExists(format!("address {a}"))),
            r => r.map(|_| ()).map_err(Into::into),
        }
    }

    pub fn remove_address(&self, address: &str) -> Result<(), StoreError> {
        let a = address.to_lowercase();
        match self.writer().execute("DELETE FROM addresses WHERE address = ?", [&a])? {
            0 => Err(StoreError::NotFound(format!("address {a}"))),
            _ => Ok(()),
        }
    }

    /// Every registered address with the login it routes to, sorted by address.
    pub fn exact_recipient(&self, address: &str) -> Result<Option<AccountId>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT account_id FROM addresses WHERE address = ?")?;
        Ok(st.query_row([address.to_lowercase()], |r| r.get(0)).optional()?.map(AccountId))
    }

    pub fn addresses(&self) -> Result<Vec<(String, String)>, StoreError> {
        let c = self.reader();
        let mut st = c.prepare_cached(
            "SELECT a.address, c.login FROM addresses a JOIN accounts c ON c.id = a.account_id ORDER BY a.address",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Lowercase, strip "+tag" from the local part, exact lookup, then "@domain".
    /// Domain = after the last '@'. Empty local part or domain: no route.
    pub fn route(&self, envelope_to: &str) -> Result<Option<AccountId>, StoreError> {
        let a = envelope_to.to_lowercase();
        let Some((local, domain)) = a.rsplit_once('@') else { return Ok(None) };
        if local.is_empty() || domain.is_empty() {
            return Ok(None);
        }
        let base = local.split('+').next().unwrap_or("");
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT account_id FROM addresses WHERE address = ?")?;
        if !base.is_empty()
            && let Some(id) = st.query_row([format!("{base}@{domain}")], |r| r.get(0)).optional()? {
                return Ok(Some(AccountId(id)));
            }
        Ok(st.query_row([format!("@{domain}")], |r| r.get(0)).optional()?.map(AccountId))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_login_tells_a_disabled_account_with_the_right_password_apart() {
        const LOGIN: &str = "user@example.com";
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("data")).unwrap();
        store.create_account(LOGIN, "right-password").unwrap();
        assert!(matches!(store.verify_login(LOGIN, "right-password").unwrap(), Verified::Valid(a) if a.login == LOGIN));
        assert!(matches!(store.verify_login(LOGIN, "wrong-password").unwrap(), Verified::Invalid));

        store.set_disabled(LOGIN, true).unwrap();
        assert!(matches!(store.verify_login(LOGIN, "right-password").unwrap(), Verified::Disabled));
        assert!(matches!(store.verify_login(LOGIN, "wrong-password").unwrap(), Verified::Invalid));
        assert!(matches!(store.verify_login("nobody@example.com", "right-password").unwrap(), Verified::Invalid));
        assert_eq!(store.authenticate(LOGIN, "right-password").unwrap(), None, "authenticate still refuses a disabled account");
    }
}
