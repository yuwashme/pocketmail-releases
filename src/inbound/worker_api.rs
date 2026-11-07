//! Client for the inbound Worker's pull API, contract v1. Also accepts the v0 contract: no `complete`
//! field (= complete), no X-SSM-* headers (envelope "" => quarantine; size = body as framed by HTTP).

use std::fmt;
use std::io;
use std::path::Path;

use super::http::{self, BodyFile, Head, HttpClient, HttpError, Method};

/// Cap on the `GET /messages` JSON body (1,000 keys are ~60 KB).
pub const MAX_LIST_BYTES: u64 = 1024 * 1024;
/// Cap on the body of a DELETE answer (204 has none).
const MAX_DELETE_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum ApiError {
    /// 401 from the Worker (wrong or missing token).
    Unauthorized,
    /// Any other unexpected status.
    Status(u16),
    Http(HttpError),
    /// Unparsable JSON, wrong JSON shape, bad percent-encoding in an envelope header, bad X-SSM-Size.
    BadResponse(String),
    /// Body length differs from X-SSM-Size.
    SizeMismatch { expected: u64, actual: u64 },
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Unauthorized => f.write_str("401 from the Worker: check the pull token"),
            ApiError::Status(s) => write!(f, "unexpected status {s} from the Worker"),
            ApiError::Http(e) => write!(f, "{e}"),
            ApiError::BadResponse(m) => write!(f, "bad response from the Worker: {m}"),
            ApiError::SizeMismatch { expected, actual } => write!(f, "X-SSM-Size {expected} but {actual} bytes received"),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<HttpError> for ApiError {
    fn from(e: HttpError) -> Self {
        ApiError::Http(e)
    }
}

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::BadResponse(m.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// As the Worker sent them (oldest first in contract v1).
    pub ids: Vec<String>,
    /// false => list again at once. Missing in the JSON (v0 Worker) => true.
    pub complete: bool,
}

#[derive(Debug)]
pub struct Fetched {
    /// Percent-decoded X-SSM-Envelope-From; "" when the header is missing.
    pub envelope_from: String,
    /// Percent-decoded X-SSM-Envelope-To; "" when the header is missing.
    pub envelope_to: String,
    /// X-SSM-Size (verified = body.len()); body.len() when the header is missing.
    pub size: u64,
    pub body: BodyFile,
}

#[derive(Debug)]
pub enum Fetch {
    Message(Fetched),
    /// 404: already gone from KV (acked earlier or expired).
    Gone,
}

/// The arrival time in unix ms from a key `msg:<exactly 13 digits>:<non-empty id>`; None otherwise.
pub fn parse_key(key: &str) -> Option<i64> {
    let (ms, id) = key.strip_prefix("msg:")?.split_once(':')?;
    if ms.len() != 13 || !ms.bytes().all(|b| b.is_ascii_digit()) || id.is_empty() {
        return None;
    }
    ms.parse().ok()
}

/// The pull token from SSM_PULL_TOKEN_FILE, surrounding whitespace trimmed. Empty => InvalidData.
pub fn read_token_file(path: &Path) -> io::Result<String> {
    let token = std::fs::read_to_string(path)?.trim().to_string();
    if token.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pull token file is empty"));
    }
    Ok(token)
}

/// Percent-encode a path segment: everything but RFC 3986 unreserved characters and ':'.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Strict percent-decoding (as JavaScript's decodeURIComponent): every '%' needs two hex digits
/// and the result must be UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok().filter(|_| hex.iter().all(u8::is_ascii_hexdigit))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// 401 => Unauthorized, other non-2xx => Status.
fn check(head: &Head) -> Result<(), ApiError> {
    match head.status {
        200..=299 => Ok(()),
        401 => Err(ApiError::Unauthorized),
        s => Err(ApiError::Status(s)),
    }
}

pub struct WorkerApi {
    client: HttpClient,
    base: String,
    auth: String,
}

impl WorkerApi {
    /// `base_url` is SSM_PULL_URL (https only; a trailing '/' is ignored; a path prefix is kept).
    /// Every request sends `Authorization: Bearer <token>`.
    pub fn new(client: HttpClient, base_url: &str, token: &str) -> Result<WorkerApi, ApiError> {
        let base = base_url.trim_end_matches('/').to_string();
        http::parse_url(&format!("{base}/messages"))?;
        Ok(WorkerApi { client, base, auth: format!("Bearer {token}") })
    }

    fn headers(&self) -> [(&str, &str); 1] {
        [("Authorization", self.auth.as_str())]
    }

    fn message_url(&self, id: &str) -> String {
        format!("{}/messages/{}", self.base, encode_segment(id))
    }

    /// `GET <base>/messages`, exactly one request.
    pub async fn list(&self) -> Result<Listing, ApiError> {
        let url = format!("{}/messages", self.base);
        let (head, body) = self.client.send(Method::Get, &url, &self.headers(), MAX_LIST_BYTES).await?;
        check(&head)?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| bad(format!("list JSON: {e}")))?;
        let ids = v
            .get("ids")
            .and_then(|i| i.as_array())
            .ok_or_else(|| bad("list without an ids array"))?
            .iter()
            .map(|i| i.as_str().map(str::to_string).ok_or_else(|| bad("non-string id in list")))
            .collect::<Result<Vec<_>, _>>()?;
        let complete = match v.get("complete") {
            None => true,
            Some(c) => c.as_bool().ok_or_else(|| bad("complete is not a boolean"))?,
        };
        Ok(Listing { ids, complete })
    }

    /// `GET <base>/messages/<id>`, body streamed into a file in `tmp_dir`. No file is left in
    /// `tmp_dir` unless `Fetch::Message` is returned.
    pub async fn fetch(&self, id: &str, tmp_dir: &Path) -> Result<Fetch, ApiError> {
        let (head, body) = self.client.get_to_file(&self.message_url(id), &self.headers(), tmp_dir).await?;
        if head.status == 404 {
            return Ok(Fetch::Gone);
        }
        check(&head)?;
        let envelope = |name: &str| match head.header(name) {
            None => Ok(String::new()),
            Some(v) => percent_decode(v).ok_or_else(|| bad(format!("bad percent-encoding in {name}"))),
        };
        let envelope_from = envelope("X-SSM-Envelope-From")?;
        let envelope_to = envelope("X-SSM-Envelope-To")?;
        let size = match head.header("X-SSM-Size") {
            None => body.len(),
            Some(v) => {
                let v = v.trim();
                let expected = v
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| v.parse::<u64>().ok())
                    .flatten()
                    .ok_or_else(|| bad("X-SSM-Size is not a number"))?;
                if expected != body.len() {
                    return Err(ApiError::SizeMismatch { expected, actual: body.len() });
                }
                expected
            }
        };
        Ok(Fetch::Message(Fetched { envelope_from, envelope_to, size, body }))
    }

    /// `DELETE <base>/messages/<id>`: any 2xx => Ok.
    pub async fn delete(&self, id: &str) -> Result<(), ApiError> {
        let (head, _) = self.client.send(Method::Delete, &self.message_url(id), &self.headers(), MAX_DELETE_BYTES).await?;
        check(&head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("a%40b%C5%A1").as_deref(), Some("a@bš"));
        for bad in ["%", "%4", "%+1", "%zz", "%C5"] {
            assert_eq!(percent_decode(bad), None, "{bad}");
        }
    }
}
