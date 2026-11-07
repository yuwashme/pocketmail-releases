//! Signed-in sessions and the sign-in rate limit, in memory with a fixed maximum size. Expiry is
//! checked on use, so nothing here runs a timer.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use crate::store::AccountId;

pub const COOKIE: &str = "__Host-ssm_session";
pub const IDLE: Duration = Duration::from_secs(30 * 60);
pub const MAX_AGE: Duration = Duration::from_secs(12 * 3600);
/// Entries per table; past it the oldest one is dropped.
pub const CAP: usize = 1000;
pub const WINDOW: Duration = Duration::from_secs(15 * 60);
pub const IP_FAILURES: u32 = 5;
pub const LOGIN_FAILURES: u32 = 10;

pub(super) type Digest = [u8; 32];

pub(super) fn sha256(bytes: &[u8]) -> Digest {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

pub(super) fn random() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("the system random number generator");
    b
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 64 lowercase hex digits to the 32 bytes they spell.
fn unhex(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in s.chunks(2).enumerate() {
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

/// Equal length and contents, in time that depends only on the length.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

/// What a request's session gives the pages.
pub struct Session {
    pub account: AccountId,
    /// The account's `auth_stamp` when the session started (or was last renewed).
    pub stamp: i64,
    pub csrf: String,
}

struct Entry {
    account: AccountId,
    stamp: i64,
    csrf: [u8; 32],
    created: Duration,
    seen: Duration,
    /// When it was last used, in uses of the table: the order to drop sessions in, even when
    /// the clock has not moved between uses.
    used: u64,
}

#[derive(Default)]
struct Table {
    /// Keyed by the SHA-256 of the id, so the table never holds a usable cookie value.
    map: HashMap<Digest, Entry>,
    uses: u64,
}

#[derive(Default)]
pub struct Sessions(Mutex<Table>);

impl Sessions {
    /// A new session; returns the cookie value (256 random bits as hex).
    pub fn create(&self, account: AccountId, stamp: i64, now: Duration) -> String {
        let id = random();
        let mut t = crate::store::lock(&self.0);
        if t.map.len() >= CAP
            && let Some(oldest) = t.map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| *k)
        {
            t.map.remove(&oldest);
        }
        t.uses += 1;
        let used = t.uses;
        t.map.insert(sha256(&id), Entry { account, stamp, csrf: random(), created: now, seen: now, used });
        hex(&id)
    }

    /// The live session for a cookie value; restarts its idle time. An expired one is removed.
    pub fn get(&self, cookie: &str, now: Duration) -> Option<Session> {
        let key = sha256(&unhex(cookie)?);
        let mut t = crate::store::lock(&self.0);
        t.uses += 1;
        let used = t.uses;
        let e = t.map.get_mut(&key)?;
        if now.saturating_sub(e.seen) > IDLE || now.saturating_sub(e.created) > MAX_AGE {
            t.map.remove(&key);
            return None;
        }
        (e.seen, e.used) = (now, used);
        Some(Session { account: e.account, stamp: e.stamp, csrf: hex(&e.csrf) })
    }

    /// Keep the session after its own password change gave the account a new stamp.
    pub fn renew(&self, cookie: &str, stamp: i64) {
        if let Some(id) = unhex(cookie)
            && let Some(e) = crate::store::lock(&self.0).map.get_mut(&sha256(&id))
        {
            e.stamp = stamp;
        }
    }

    pub fn remove(&self, cookie: &str) {
        if let Some(id) = unhex(cookie) {
            crate::store::lock(&self.0).map.remove(&sha256(&id));
        }
    }
}

/// IPv4 addresses one by one, IPv6 by /64 (one network's worth of addresses is one client).
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        },
    }
}

struct Count {
    /// Start of the window; moved to the failure that locks, so a lock lasts a whole window.
    since: Duration,
    failures: u32,
}

struct Counts<K> {
    map: HashMap<K, Count>,
}

impl<K> Default for Counts<K> {
    fn default() -> Counts<K> {
        Counts { map: HashMap::new() }
    }
}

impl<K: std::hash::Hash + Eq + Copy> Counts<K> {
    fn left(&self, key: &K, limit: u32, now: Duration) -> Option<Duration> {
        let c = self.map.get(key).filter(|c| c.failures >= limit)?;
        (c.since + WINDOW).checked_sub(now).filter(|d| !d.is_zero())
    }

    fn fail(&mut self, key: K, limit: u32, now: Duration) {
        if !self.map.contains_key(&key) && self.map.len() >= CAP {
            self.map.retain(|_, c| now.saturating_sub(c.since) < WINDOW);
            if self.map.len() >= CAP
                && let Some(oldest) = self.map.iter().min_by_key(|(_, c)| c.since).map(|(k, _)| *k)
            {
                self.map.remove(&oldest);
            }
        }
        let c = self.map.entry(key).or_insert(Count { since: now, failures: 0 });
        if now.saturating_sub(c.since) >= WINDOW {
            *c = Count { since: now, failures: 0 };
        }
        c.failures += 1;
        if c.failures == limit {
            c.since = now;
        }
    }
}

#[derive(Default)]
struct Tables {
    ips: Counts<IpAddr>,
    /// By the SHA-256 of the login as typed: fixed size, whatever was typed.
    logins: Counts<Digest>,
}

/// Failed password checks per client IP and per login.
#[derive(Default)]
pub struct Limiter(Mutex<Tables>);

impl Limiter {
    /// How long until this IP and login may try again, if either is locked.
    pub fn locked(&self, ip: IpAddr, login: &str, now: Duration) -> Option<Duration> {
        let t = crate::store::lock(&self.0);
        let by_ip = t.ips.left(&ip_key(ip), IP_FAILURES, now);
        let by_login = t.logins.left(&sha256(login.as_bytes()), LOGIN_FAILURES, now);
        by_ip.max(by_login)
    }

    pub fn failed(&self, ip: IpAddr, login: &str, now: Duration) {
        let mut t = crate::store::lock(&self.0);
        t.ips.fail(ip_key(ip), IP_FAILURES, now);
        t.logins.fail(sha256(login.as_bytes()), LOGIN_FAILURES, now);
    }

    /// Clears the login's count only: the IP's count also holds the other logins tried from it.
    pub fn succeeded(&self, _ip: IpAddr, login: &str) {
        crate::store::lock(&self.0).logins.map.remove(&sha256(login.as_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGIN: &str = "user@example.com";
    const T0: Duration = Duration::from_secs(100);

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ten_failures_lock_login_from_any_ip() {
        let l = Limiter::default();
        for i in 1..=9 {
            l.failed(ip(&format!("192.168.1.{i}")), LOGIN, T0);
        }
        assert_eq!(l.locked(ip("192.168.1.50"), LOGIN, T0), None, "nine failures do not lock");
        l.failed(ip("192.168.1.10"), LOGIN, T0);
        assert_eq!(l.locked(ip("192.168.1.50"), LOGIN, T0), Some(WINDOW), "ten lock the login from a new IP");
        assert_eq!(l.locked(ip("192.168.1.50"), "other@example.com", T0), None, "other logins are not locked");
        assert_eq!(l.locked(ip("192.168.1.50"), LOGIN, T0 + WINDOW), None, "the lock ends after the window");
    }

    #[test]
    fn ipv6_counted_per_64() {
        let l = Limiter::default();
        for i in 1..=5 {
            l.failed(ip(&format!("fd00:1:2:3::{i}")), &format!("u{i}@example.com"), T0);
        }
        assert!(l.locked(ip("fd00:1:2:3:ffff::1"), LOGIN, T0).is_some(), "the same /64 is locked");
        assert_eq!(l.locked(ip("fd00:1:2:4::1"), LOGIN, T0), None, "another /64 is not");
        for i in 1..=5 {
            l.failed(ip("::ffff:192.168.1.9"), &format!("v{i}@example.com"), T0);
        }
        assert!(l.locked(ip("192.168.1.9"), LOGIN, T0).is_some(), "an IPv4-mapped address is its IPv4 address");
        assert_eq!(l.locked(ip("192.168.1.8"), LOGIN, T0), None, "IPv4 addresses count one by one");
    }

    #[test]
    fn tables_capped_1000_oldest_dropped() {
        let s = Sessions::default();
        let first = s.create(AccountId(1), 1, T0);
        let second = s.create(AccountId(1), 1, T0 + Duration::from_secs(1));
        for i in 0..CAP as u64 - 2 {
            s.create(AccountId(1), 1, T0 + Duration::from_secs(2 + i));
        }
        assert!(s.get(&first, T0 + Duration::from_secs(1000)).is_some(), "full, nothing dropped yet");
        s.create(AccountId(1), 1, T0 + Duration::from_secs(1001));
        assert_eq!(crate::store::lock(&s.0).map.len(), CAP);
        assert!(s.get(&second, T0 + Duration::from_secs(1001)).is_none(), "the session seen longest ago is dropped");
        assert!(s.get(&first, T0 + Duration::from_secs(1001)).is_some(), "a recently seen one stays");

        let l = Limiter::default();
        for i in 0..CAP as u32 + 1 {
            let at = T0 + Duration::from_millis(u64::from(i));
            let [_, _, a, b] = i.to_be_bytes();
            l.failed(ip(&format!("10.0.{a}.{b}")), &format!("u{i}@example.com"), at);
        }
        let t = crate::store::lock(&l.0);
        assert_eq!((t.ips.map.len(), t.logins.map.len()), (CAP, CAP));
        assert!(!t.ips.map.contains_key(&ip("10.0.0.0")), "the oldest IP is dropped");
        assert!(!t.logins.map.contains_key(&sha256(b"u0@example.com")), "the oldest login is dropped");
        assert!(t.ips.map.contains_key(&ip("10.0.0.1")));
    }

    #[test]
    fn table_holds_only_hashed_ids() {
        let s = Sessions::default();
        let cookie = s.create(AccountId(7), 42, T0);
        let raw = unhex(&cookie).expect("64 hex digits");
        let t = crate::store::lock(&s.0);
        let (key, entry) = t.map.iter().next().unwrap();
        assert_eq!(*key, sha256(&raw));
        assert_ne!(key, &raw);
        assert_ne!(entry.csrf, raw, "the token is not the id");
    }

    #[test]
    fn sessions_expire_on_use() {
        let s = Sessions::default();
        let c = s.create(AccountId(1), 1, T0);
        assert!(s.get(&c, T0 + IDLE).is_some());
        assert!(s.get(&c, T0 + IDLE + IDLE + Duration::from_secs(1)).is_none(), "idle too long");
        assert!(s.get(&c, T0).is_none(), "and gone");
        assert!(s.get(&c.to_uppercase(), T0).is_none() && s.get("ab", T0).is_none());
    }

    #[test]
    fn same_compares_contents_and_length() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd") && !same(b"abc", b"ab") && !same(b"", b"a"));
    }
}
