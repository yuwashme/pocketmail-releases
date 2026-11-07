//! Configuration from environment variables only. An empty value counts as unset; variables this binary does not know are ignored.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::log::Level;

/// KV free tier allows 1,000 lists a day; 120 s is 720 a day.
pub const MIN_PULL_INTERVAL_SECS: u64 = 120;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub pull_url: Option<String>,
    pub pull_token_file: Option<PathBuf>,
    pub pull_interval: Duration,
    pub imap_listen: SocketAddr,
    pub imap_max_conn: usize,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Settings pages over HTTPS; None when SSM_WEB_LISTEN is "off".
    pub web_listen: Option<SocketAddr>,
    /// Serve the settings pages to clients outside the home network too (SSM_WEB_ALLOW_PUBLIC=yes).
    pub web_allow_public: bool,
    /// One of error, warn, info, debug (lowercase); default "info".
    pub log: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(String),
    Invalid { var: String, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Missing(v) => write!(f, "{v} must be set"),
            ConfigError::Invalid { var, reason } => write!(f, "{var}: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(var: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { var: var.to_string(), reason: reason.into() }
}

/// Plain decimal digits only ("+5", "-5", "1e3", "120s" are rejected).
fn number(var: &str, v: &str) -> Result<u64, ConfigError> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(var, "must be a whole number"));
    }
    v.parse().map_err(|_| invalid(var, "number too large"))
}

impl Config {
    pub fn from_env() -> Result<Config, ConfigError> {
        Config::from_vars(std::env::vars())
    }

    pub fn from_vars<I, K, V>(vars: I) -> Result<Config, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let vars: HashMap<String, String> = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .filter(|(k, v)| k.starts_with("SSM_") && !v.is_empty())
            .collect();
        let get = |k: &str| vars.get(k).map(String::as_str);

        let data_dir = PathBuf::from(get("SSM_DATA_DIR").ok_or_else(|| ConfigError::Missing("SSM_DATA_DIR".into()))?);

        let pull_url = match get("SSM_PULL_URL") {
            None => None,
            Some(u) => {
                let host = u.strip_prefix("https://").unwrap_or("");
                if host.is_empty() || host.starts_with('/') {
                    return Err(invalid("SSM_PULL_URL", "must be an https:// URL"));
                }
                Some(u.to_string())
            }
        };
        let pull_token_file = get("SSM_PULL_TOKEN_FILE").map(PathBuf::from);
        if pull_url.is_some() && pull_token_file.is_none() {
            return Err(ConfigError::Missing("SSM_PULL_TOKEN_FILE".into()));
        }

        let pull_interval = match get("SSM_PULL_INTERVAL_SECS") {
            None => Duration::from_secs(MIN_PULL_INTERVAL_SECS),
            Some(v) => {
                let secs = number("SSM_PULL_INTERVAL_SECS", v)?;
                if secs < MIN_PULL_INTERVAL_SECS {
                    return Err(invalid("SSM_PULL_INTERVAL_SECS", format!("at least {MIN_PULL_INTERVAL_SECS} (KV list quota)")));
                }
                Duration::from_secs(secs)
            }
        };

        let imap_listen = get("SSM_IMAP_LISTEN")
            .unwrap_or("0.0.0.0:9993")
            .parse()
            .map_err(|_| invalid("SSM_IMAP_LISTEN", "must be address:port"))?;

        let imap_max_conn = match get("SSM_IMAP_MAX_CONN") {
            None => 100,
            Some(v) => match number("SSM_IMAP_MAX_CONN", v)? {
                0 => return Err(invalid("SSM_IMAP_MAX_CONN", "must be at least 1")),
                n => usize::try_from(n).map_err(|_| invalid("SSM_IMAP_MAX_CONN", "number too large"))?,
            },
        };

        let tls_cert = get("SSM_TLS_CERT").map(PathBuf::from);
        let tls_key = get("SSM_TLS_KEY").map(PathBuf::from);
        match (&tls_cert, &tls_key) {
            (Some(_), None) => return Err(invalid("SSM_TLS_KEY", "must be set together with SSM_TLS_CERT")),
            (None, Some(_)) => return Err(invalid("SSM_TLS_CERT", "must be set together with SSM_TLS_KEY")),
            _ => {}
        }

        let web_listen = match get("SSM_WEB_LISTEN").unwrap_or("0.0.0.0:8443") {
            "off" => None,
            v => Some(v.parse().map_err(|_| invalid("SSM_WEB_LISTEN", "must be address:port or off"))?),
        };
        let web_allow_public = match get("SSM_WEB_ALLOW_PUBLIC") {
            None | Some("no") => false,
            Some("yes") => true,
            Some(_) => return Err(invalid("SSM_WEB_ALLOW_PUBLIC", "must be yes or no")),
        };

        let log = get("SSM_LOG").unwrap_or("info").to_ascii_lowercase();
        if Level::parse(&log).is_none() {
            return Err(invalid("SSM_LOG", "must be error, warn, info or debug"));
        }

        Ok(Config {
            data_dir,
            pull_url,
            pull_token_file,
            pull_interval,
            imap_listen,
            imap_max_conn,
            tls_cert,
            tls_key,
            web_listen,
            web_allow_public,
            log,
        })
    }
}
