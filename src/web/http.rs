//! HTTP/1.1 request heads (RFC 9112) and responses, without I/O. Requests are limited to an 8 KiB
//! head, 32 header fields and a 16 KiB body (256 KiB for compose submissions).
//! Transfer-Encoding is not supported.

use std::borrow::Cow;

pub const MAX_HEAD: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 32;
pub const MAX_BODY: usize = 16 * 1024;

pub(super) const COMPOSE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    /// Percent-decoded path, without the query.
    pub path: String,
    /// The query as sent, without the `?`.
    pub query: String,
    /// The Host header ("" for HTTP/1.0 without one).
    pub host: String,
    /// The Origin header, if there is exactly one.
    pub origin: Option<String>,
    /// The Cookie headers, joined with "; ".
    pub cookies: String,
    pub content_length: usize,
    /// `Content-Type: application/x-www-form-urlencoded` (parameters allowed).
    pub form: bool,
    /// HTTP/1.1 without `Connection: close`.
    pub keep_alive: bool,
    /// A Forwarded, X-Forwarded-For, X-Real-IP or CF-Connecting-IP header: sent through a proxy.
    pub proxied: bool,
    pub cf_client: Option<std::net::IpAddr>,
}

impl Request {
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.split(';').filter_map(|c| c.trim().split_once('=')).find(|(n, _)| *n == name).map(|(_, v)| v)
    }
}

/// Parse the request head at the start of `buf`. `Ok(None)`: incomplete, read more. `Ok(Some)`:
/// the request and the head's length. `Err(status)`: answer with that status and close.
pub fn parse_head(buf: &[u8]) -> Result<Option<(Request, usize)>, u16> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let len = match req.parse(&buf[..buf.len().min(MAX_HEAD)]) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) if buf.len() >= MAX_HEAD => return Err(431),
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(431),
        Err(_) => return Err(400),
    };
    let http10 = req.version == Some(0);
    let values = |name: &str| req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value).collect::<Vec<_>>();

    let hosts = values("host");
    if hosts.len() > 1 || (hosts.is_empty() && !http10) {
        return Err(400);
    }
    let text = |v: &[u8]| std::str::from_utf8(v).ok().map(str::to_string);
    let host = hosts.first().and_then(|v| text(v)).unwrap_or_default();
    let origin = match values("origin").as_slice() {
        [v] => text(v),
        _ => None,
    };
    let cookies = values("cookie").into_iter().filter_map(text).collect::<Vec<_>>().join("; ");
    let (path, query) = decode_target(req.path.unwrap_or_default()).ok_or(400u16)?;

    let lengths = values("content-length");
    if !values("transfer-encoding").is_empty() {
        return Err(if lengths.is_empty() { 501 } else { 400 });
    }
    let content_length = match lengths.as_slice() {
        [] => None,
        [v] => Some(parse_length(v, if req.method == Some("POST") && path == "/compose" { 256 * 1024 } else { MAX_BODY })?),
        _ => return Err(400),
    };
    let method = match req.method.unwrap_or_default() {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "TRACE" | "CONNECT" => return Err(405),
        _ => return Err(501),
    };
    if method == Method::Post && content_length.is_none() {
        return Err(411);
    }

    let form = values("content-type").first().is_some_and(|v| {
        let media = v.split(|&b| b == b';').next().unwrap_or_default();
        media.trim_ascii().eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
    });
    let close = values("connection").iter().any(|v| v.split(|&b| b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(b"close")));
    let keep_alive = !http10 && !close;
    let proxied = ["forwarded", "x-forwarded-for", "x-real-ip", "cf-connecting-ip"].iter().any(|name| !values(name).is_empty());
    let cf_client = match values("cf-connecting-ip").as_slice() {
        [value] => std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()),
        _ => None,
    };
    let request = Request { cf_client, method, path, query, host, origin, cookies, content_length: content_length.unwrap_or(0), form, keep_alive, proxied };
    Ok(Some((request, len)))
}

/// Decimal digits only; 400 if malformed, 413 if over the route limit (however many digits).
fn parse_length(v: &[u8], limit: usize) -> Result<usize, u16> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return Err(400);
    }
    v.iter()
        .try_fold(0usize, |n, d| n.checked_mul(10)?.checked_add(usize::from(d - b'0')))
        .filter(|&n| n <= limit)
        .ok_or(413)
}

/// Origin-form (or absolute-form, RFC 9112 3.2.2) target to a decoded path and the raw query;
/// None if malformed.
fn decode_target(target: &str) -> Option<(String, String)> {
    let lower = target.get(..8).unwrap_or(target).to_ascii_lowercase();
    let target = match ["http://", "https://"].iter().find(|s| lower.starts_with(*s)) {
        Some(scheme) => target[scheme.len()..].find('/').map_or("/", |i| &target[scheme.len() + i..]),
        None => target,
    };
    if !target.is_ascii() || !target.starts_with('/') {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some((percent_decode(path.as_bytes(), false)?, query.to_string()))
}

/// `application/x-www-form-urlencoded` pairs in order; None on a bad escape or invalid UTF-8.
pub fn decode_form(body: &[u8]) -> Option<Vec<(String, String)>> {
    body.split(|&b| b == b'&')
        .filter(|piece| !piece.is_empty())
        .map(|piece| {
            let (name, value) = match piece.iter().position(|&b| b == b'=') {
                Some(i) => (&piece[..i], &piece[i + 1..]),
                None => (piece, &[][..]),
            };
            Some((percent_decode(name, true)?, percent_decode(value, true)?))
        })
        .collect()
}

fn percent_decode(s: &[u8], plus_is_space: bool) -> Option<String> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push((hex(*s.get(i + 1)?)? << 4) | hex(*s.get(i + 2)?)?);
                i += 3;
                continue;
            }
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub cache_control: &'static str,
    pub body: Cow<'static, [u8]>,
    /// More header fields, such as Location and Set-Cookie.
    pub headers: Vec<(&'static str, String)>,
}

impl Response {
    /// A short HTML page naming the status, saying why in general terms, with a link to the start.
    pub fn error(status: u16) -> Response {
        let why = match status {
            400 => "The request could not be read.",
            403 => "You cannot open this page.",
            404 => "There is no page at this address.",
            408 => "The request took too long to arrive.",
            500 => "Something went wrong on the server. Its log has the details.",
            _ => "The request could not be handled.",
        };
        Response::error_because(status, why)
    }

    /// `error` with its own reason: markup written in the source.
    pub fn error_because(status: u16, why: &'static str) -> Response {
        let reason = reason(status);
        let css = super::CSS_PATH;
        let html = format!(
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
             <title>{status} {reason}</title><link rel=\"stylesheet\" href=\"{css}\"></head>\
             <body><main><h1>{reason}</h1><p>{why}</p><p><a href=\"/\">Go to the start page</a></p></main></body></html>\n"
        );
        Response::html(status, html.into_bytes())
    }

    pub fn html(status: u16, body: Vec<u8>) -> Response {
        Response { status, content_type: "text/html; charset=utf-8", cache_control: "no-store", body: Cow::Owned(body), headers: Vec::new() }
    }

    /// Status line, headers and (unless `head_only`) the body. `date` is the IMF-fixdate.
    pub fn encode(&self, head_only: bool, close: bool, date: &str) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nDate: {date}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: {}\r\n\
             X-Content-Type-Options: nosniff\r\nReferrer-Policy: same-origin\r\n\
             X-Frame-Options: DENY\r\n",
            self.status,
            reason(self.status),
            self.content_type,
            self.body.len(),
            self.cache_control,
        );
        if !self.headers.iter().any(|(name, _)| *name == "Content-Security-Policy") {
            out.push_str("Content-Security-Policy: ");
            out.push_str(CSP);
            out.push_str("\r\n");
        }
        if self.status == 405 {
            out.push_str("Allow: GET, HEAD, POST\r\n");
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        if close {
            out.push_str("Connection: close\r\n");
        }
        out.push_str("\r\n");
        let mut out = out.into_bytes();
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Error",
    }
}
