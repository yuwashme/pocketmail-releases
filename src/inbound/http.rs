//! Hand-written HTTP/1.1 client over rustls: one TLS connection per request, `Connection: close`, no
//! Accept-Encoding, response framing per RFC 9112 section 6.3, header block capped at 64 KiB,
//! large bodies streamed to a file and never buffered whole.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Cap on the response status line + header fields + final CRLF.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// No byte received (or sent) for this long => `HttpError::Timeout`.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bytes asked from the TLS stream per read.
const READ_CHUNK: usize = 16 * 1024;
/// Header fields per response (httparse needs a fixed array).
const MAX_HEADERS: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Debug)]
pub enum HttpError {
    /// Not `https://host[:port][/path]`.
    InvalidUrl(String),
    /// Connect, read or write failed (not a TLS verification problem).
    Io(io::Error),
    /// TLS handshake failed: untrusted certificate, wrong host name, protocol error.
    Tls(String),
    /// Nothing received or sent for the idle timeout.
    Timeout,
    /// Status line + headers longer than MAX_HEAD_BYTES.
    HeadTooLarge,
    /// Unparsable status line, header, chunk size or conflicting Content-Length values.
    Malformed(String),
    /// The body ended before its framing said it would: short Content-Length, missing last
    /// chunk, or a close-delimited body ended without a TLS close_notify (RFC 9112 9.8).
    Truncated,
    /// `send` only: the body is larger than its `max_body`.
    BodyTooLarge { limit: u64 },
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::InvalidUrl(u) => write!(f, "invalid URL {u:?} (https://host[:port][/path] only)"),
            HttpError::Io(e) => write!(f, "I/O error: {e}"),
            HttpError::Tls(e) => write!(f, "TLS error: {e}"),
            HttpError::Timeout => f.write_str("idle timeout"),
            HttpError::HeadTooLarge => write!(f, "response head over {MAX_HEAD_BYTES} bytes"),
            HttpError::Malformed(m) => write!(f, "malformed response: {m}"),
            HttpError::Truncated => f.write_str("response body truncated"),
            HttpError::BodyTooLarge { limit } => write!(f, "response body over {limit} bytes"),
        }
    }
}

impl std::error::Error for HttpError {}

fn malformed(m: &str) -> HttpError {
    HttpError::Malformed(m.to_string())
}

/// rustls errors come wrapped in io::Error (kind InvalidData); everything else is plain I/O.
fn map_io(e: io::Error) -> HttpError {
    if e.kind() == io::ErrorKind::InvalidData || e.get_ref().is_some_and(|i| i.is::<rustls::Error>()) {
        HttpError::Tls(e.to_string())
    } else {
        HttpError::Io(e)
    }
}

/// Status and header fields of a response.
#[derive(Clone, Debug)]
pub struct Head {
    pub status: u16,
    /// In received order; names as received.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Value of the first field named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A response body saved to a 0600 file. The file is deleted when this is dropped.
#[derive(Debug)]
pub struct BodyFile {
    path: PathBuf,
    len: u64,
}

impl BodyFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Number of body bytes in the file (after de-chunking).
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// A new read handle positioned at the start.
    pub fn open(&self) -> io::Result<File> {
        File::open(&self.path)
    }
}

impl Drop for BodyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// `https://host[:port][/path]` split up.
pub(crate) struct Url {
    host: String,
    port: u16,
    /// The Host header value: host as written, plus ":port" if the URL had one.
    authority: String,
    path: String,
}

pub(crate) fn parse_url(url: &str) -> Result<Url, HttpError> {
    let bad = || HttpError::InvalidUrl(url.to_string());
    let rest = url.strip_prefix("https://").ok_or_else(bad)?;
    // No whitespace or control bytes anywhere: they would break the request line.
    if rest.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(bad());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    // "[v6]:port", "[v6]", "host:port", "host"
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(bad)?;
        match after.strip_prefix(':') {
            Some(p) => (h, Some(p)),
            None if after.is_empty() => (h, None),
            None => return Err(bad()),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => 443,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?,
        Some(_) => return Err(bad()),
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok(Url { host: host.to_string(), port, authority: authority.to_string(), path: path.to_string() })
}

/// The connection plus unread bytes received ahead of their use.
struct Conn {
    stream: TlsStream<TcpStream>,
    buf: Vec<u8>,
    start: usize,
    idle: Duration,
}

impl Conn {
    fn avail(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Read more. Ok(0) only after a TLS close_notify; a bare TCP close is `Truncated`.
    async fn fill(&mut self) -> Result<usize, HttpError> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let old = self.buf.len();
        self.buf.resize(old + READ_CHUNK, 0);
        let r = timeout(self.idle, self.stream.read(&mut self.buf[old..])).await;
        let (n, res) = match r {
            Ok(Ok(n)) => (n, Ok(n)),
            // rustls: the peer closed TCP without close_notify.
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => (0, Err(HttpError::Truncated)),
            Ok(Err(e)) => (0, Err(map_io(e))),
            Err(_) => (0, Err(HttpError::Timeout)),
        };
        self.buf.truncate(old + n);
        res
    }

    /// Like `fill`, but the end of the stream is an error: the framing promised more.
    async fn fill_more(&mut self) -> Result<(), HttpError> {
        match self.fill().await? {
            0 => Err(HttpError::Truncated),
            _ => Ok(()),
        }
    }

    /// One line without its CRLF (or bare LF), for chunk sizes and trailer fields.
    async fn line(&mut self) -> Result<Vec<u8>, HttpError> {
        loop {
            if let Some(i) = self.avail().iter().position(|b| *b == b'\n') {
                let line = self.avail()[..i].strip_suffix(b"\r").unwrap_or(&self.avail()[..i]).to_vec();
                self.consume(i + 1);
                return Ok(line);
            }
            if self.avail().len() > MAX_HEAD_BYTES {
                return Err(malformed("line too long"));
            }
            self.fill_more().await?;
        }
    }

    /// Pass exactly `n` body bytes to `sink`.
    async fn copy(&mut self, mut n: u64, sink: &mut dyn FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
        while n > 0 {
            if self.avail().is_empty() {
                self.fill_more().await?;
            }
            let take = (self.avail().len() as u64).min(n) as usize;
            sink(&self.avail()[..take])?;
            self.consume(take);
            n -= take as u64;
        }
        Ok(())
    }

    /// Status line and header fields; interim 1xx responses are skipped.
    async fn head(&mut self) -> Result<Head, HttpError> {
        loop {
            let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut res = httparse::Response::new(&mut fields);
            match res.parse(self.avail()) {
                Ok(httparse::Status::Complete(n)) if n > MAX_HEAD_BYTES => return Err(HttpError::HeadTooLarge),
                Ok(httparse::Status::Complete(n)) => {
                    let status = res.code.unwrap_or(0);
                    let headers = res
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                        .collect();
                    self.consume(n);
                    if (100..200).contains(&status) {
                        continue;
                    }
                    return Ok(Head { status, headers });
                }
                Ok(httparse::Status::Partial) if self.avail().len() > MAX_HEAD_BYTES => return Err(HttpError::HeadTooLarge),
                Ok(httparse::Status::Partial) => self.fill_more().await?,
                Err(e) => return Err(HttpError::Malformed(e.to_string())),
            }
        }
    }

    /// The body as framed by RFC 9112 6.3, de-chunked, into `sink`.
    async fn body(&mut self, head: &Head, sink: &mut dyn FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
        if head.status == 204 || head.status == 304 {
            return Ok(());
        }
        let te: Vec<&str> = head.all("transfer-encoding").collect();
        if !te.is_empty() {
            // We never send TE or Accept-Encoding, so plain chunked is the only coding we take.
            if te.len() != 1 || !te[0].trim().eq_ignore_ascii_case("chunked") {
                return Err(malformed("unsupported transfer-encoding"));
            }
            return self.chunked(sink).await;
        }
        match content_length(head)? {
            Some(n) => self.copy(n, sink).await,
            None => loop {
                // Close-delimited: complete only at a close_notify (fill returns 0).
                if !self.avail().is_empty() {
                    sink(self.avail())?;
                    let n = self.avail().len();
                    self.consume(n);
                }
                if self.fill().await? == 0 {
                    return Ok(());
                }
            },
        }
    }

    async fn chunked(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
        loop {
            let line = self.line().await?;
            let size = line.split(|b| *b == b';').next().unwrap_or_default().trim_ascii();
            if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
                return Err(malformed("bad chunk size"));
            }
            let size = std::str::from_utf8(size)
                .ok()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or_else(|| malformed("chunk size overflows"))?;
            if size == 0 {
                // Trailer fields are read and dropped, up to the blank line.
                let mut trailers = 0;
                loop {
                    let l = self.line().await?;
                    if l.is_empty() {
                        return Ok(());
                    }
                    trailers += l.len();
                    if trailers > MAX_HEAD_BYTES {
                        return Err(HttpError::HeadTooLarge);
                    }
                }
            }
            self.copy(size, sink).await?;
            if !self.line().await?.is_empty() {
                return Err(malformed("chunk data longer than its size"));
            }
        }
    }
}

/// Content-Length, if any. Repeated fields or list values must all agree (RFC 9110 8.6).
fn content_length(head: &Head) -> Result<Option<u64>, HttpError> {
    let mut found = None;
    for v in head.all("content-length").flat_map(|v| v.split(',')) {
        let v = v.trim();
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(malformed("bad Content-Length"));
        }
        let n = v.parse::<u64>().map_err(|_| malformed("Content-Length overflows"))?;
        if found.is_some_and(|f| f != n) {
            return Err(malformed("conflicting Content-Length values"));
        }
        found = Some(n);
    }
    Ok(found)
}

#[derive(Clone)]
pub struct HttpClient {
    tls: Arc<rustls::ClientConfig>,
    idle_timeout: Duration,
}

impl HttpClient {
    /// Idle timeout DEFAULT_IDLE_TIMEOUT.
    pub fn new(tls: Arc<rustls::ClientConfig>) -> HttpClient {
        HttpClient { tls, idle_timeout: DEFAULT_IDLE_TIMEOUT }
    }

    pub fn with_idle_timeout(self, timeout: Duration) -> HttpClient {
        HttpClient { idle_timeout: timeout, ..self }
    }

    /// Connect, handshake, write the request; returns the connection with the head read.
    async fn request(&self, method: Method, url: &str, headers: &[(&str, &str)]) -> Result<(Conn, Head), HttpError> {
        let u = parse_url(url)?;
        let name = ServerName::try_from(u.host.clone()).map_err(|_| HttpError::InvalidUrl(url.to_string()))?;
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", method.as_str(), u.path, u.authority);
        for (n, v) in headers {
            if n.bytes().chain(v.bytes()).any(|b| b == b'\r' || b == b'\n') {
                return Err(malformed("CR or LF in a request header"));
            }
            req.push_str(&format!("{n}: {v}\r\n"));
        }
        req.push_str("\r\n");

        let idle = self.idle_timeout;
        let tcp = timeout(idle, TcpStream::connect((u.host.as_str(), u.port)))
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(HttpError::Io)?;
        let stream = timeout(idle, TlsConnector::from(self.tls.clone()).connect(name, tcp))
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(map_io)?;
        let mut conn = Conn { stream, buf: Vec::with_capacity(READ_CHUNK), start: 0, idle };
        timeout(idle, async {
            conn.stream.write_all(req.as_bytes()).await?;
            conn.stream.flush().await
        })
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(map_io)?;
        let head = conn.head().await?;
        Ok((conn, head))
    }

    /// One request on a new TLS connection. Sends `Host`, `Connection: close` and `headers`
    /// (e.g. Authorization); never `Accept-Encoding`. The body is kept in memory; a body larger
    /// than `max_body` is `BodyTooLarge`. Non-2xx statuses are not errors here.
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        max_body: u64,
    ) -> Result<(Head, Vec<u8>), HttpError> {
        let (mut conn, head) = self.request(method, url, headers).await?;
        let mut body = Vec::new();
        conn.body(&head, &mut |b: &[u8]| {
            if body.len() as u64 + b.len() as u64 > max_body {
                return Err(HttpError::BodyTooLarge { limit: max_body });
            }
            body.extend_from_slice(b);
            Ok(())
        })
        .await?;
        Ok((head, body))
    }

    /// GET with the body streamed into a new file in `dir` (same file system as the store's tmp/).
    /// On any error no file is left in `dir`.
    pub async fn get_to_file(&self, url: &str, headers: &[(&str, &str)], dir: &Path) -> Result<(Head, BodyFile), HttpError> {
        let (mut conn, head) = self.request(Method::Get, url, headers).await?;
        let r = getrandom::u64().map_err(|e| HttpError::Io(io::Error::other(e.to_string())))?;
        let path = dir.join(format!("download-{r:016x}.part"));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(HttpError::Io)?;
        // From here on Drop removes the file on every error path.
        let mut out = BodyFile { path, len: 0 };
        let mut len = 0u64;
        conn.body(&head, &mut |b: &[u8]| {
            file.write_all(b).map_err(HttpError::Io)?;
            len += b.len() as u64;
            Ok(())
        })
        .await?;
        out.len = len;
        Ok((head, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://h.example:8443/a/b?c").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.authority.as_str(), u.path.as_str()), ("h.example", 8443, "h.example:8443", "/a/b?c"));
        let u = parse_url("https://h.example").unwrap();
        assert_eq!((u.port, u.path.as_str()), (443, "/"));
        let u = parse_url("https://[::1]:9/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9));
        for bad in ["https://h:0/", "https://h:/", "https://[::1]x/", "https://h/a b"] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }
}
