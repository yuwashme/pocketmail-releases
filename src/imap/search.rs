//! SEARCH / UID SEARCH (RFC 3501 6.4.4): the full key set, charsets US-ASCII and UTF-8.
//!
//! The decoded key tree is copied into an owned `Key` (sequence sets resolved against the
//! session's view, dates turned into unix days, strings ASCII-lowercased) and evaluated on a
//! blocking thread. Flag, size, date and set keys use the store's metadata only; a message's blob
//! is read and parsed only when a header or body key needs it, and dropped after that message.
//!
//! Text matching is a substring test, case-insensitive for ASCII only, on decoded text: header
//! values with RFC 2047 encoded words decoded (mail-parser `HeaderForm::Text`), bodies with their
//! transfer encoding and charset decoded. Non-text body parts (attachments) are not searched.
//! Nesting is limited to 9 levels by the imap-codec parser (docs/DEVIATIONS.md).

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use imap_codec::imap_types::core::Charset;
use imap_codec::imap_types::search::SearchKey;
use imap_codec::imap_types::sequence::{SeqOrUid, Sequence, SequenceSet};
use mail_parser::{DateTime, HeaderForm, HeaderValue, MessageParser, MessagePart, MessageRef};

use super::bodystructure::header_len_from;
use super::session::{Reply, Session, State};
use crate::store::{Flags, MessageMeta, StoreError};

/// Deeper key trees are refused (the parser already stops at 9; this guards the recursion).
const MAX_DEPTH: usize = 32;

/// A search key with everything resolved that does not depend on the message.
#[derive(Debug)]
enum Key {
    And(Vec<Key>),
    Or(Box<Key>, Box<Key>),
    Not(Box<Key>),
    Const(bool),
    /// Sequence-number ranges (inclusive).
    Seq(Vec<(u32, u32)>),
    /// UID ranges (inclusive).
    Uid(Vec<(u32, u32)>),
    /// The flag is set (true) or not set (false).
    Flag(Flags, bool),
    Recent,
    Larger(u64),
    Smaller(u64),
    /// INTERNALDATE's UTC day (unix seconds at 00:00) before / on / since.
    Before(i64),
    On(i64),
    Since(i64),
    /// The Date header's own calendar day (time and zone ignored).
    SentBefore(i64),
    SentOn(i64),
    SentSince(i64),
    /// Header field (lowercase name) contains the (lowercased) string.
    Header(Vec<u8>, Vec<u8>),
    Body(Vec<u8>),
    Text(Vec<u8>),
}

impl Key {
    fn needs_content(&self) -> bool {
        match self {
            Key::And(v) => v.iter().any(Key::needs_content),
            Key::Or(a, b) => a.needs_content() || b.needs_content(),
            Key::Not(k) => k.needs_content(),
            Key::SentBefore(_) | Key::SentOn(_) | Key::SentSince(_) | Key::Header(..) | Key::Body(_) | Key::Text(_) => true,
            _ => false,
        }
    }
}

/// The charsets SEARCH accepts; anything else gets `NO [BADCHARSET]`.
fn charset_ok(c: &Charset<'_>) -> bool {
    let c: &str = c.as_ref();
    c.eq_ignore_ascii_case("US-ASCII") || c.eq_ignore_ascii_case("UTF-8")
}

pub(crate) async fn search(s: &mut Session, charset: Option<&Charset<'_>>, criteria: &SearchKey<'_>, uid: bool) -> io::Result<Reply> {
    let State::Selected(sel) = &s.state else {
        return Ok(Reply::no("No mailbox selected"));
    };
    if let Some(c) = charset
        && !charset_ok(c)
    {
        return Ok(Reply::no("[BADCHARSET (US-ASCII UTF-8)] Unsupported charset"));
    }
    let last_seq = sel.uids.len() as u32;
    let last_uid = sel.uids.last().copied().unwrap_or(0);
    let Some(key) = convert(criteria, last_seq, last_uid, 0) else {
        return Ok(Reply::bad("Invalid search criteria"));
    };
    let mailbox = sel.mailbox;
    let view: Vec<(u32, bool)> = sel.uids.iter().map(|&u| (u, sel.is_recent(u))).collect();
    let data_dir = s.store.data_dir().to_path_buf();

    let r = s
        .blocking(move |st| {
            let metas = st.messages(mailbox)?;
            let content = key.needs_content();
            let mut hits = Vec::new();
            for (i, &(u, recent)) in view.iter().enumerate() {
                // Expunged meanwhile (not possible yet): no longer matches anything.
                let Ok(m) = metas.binary_search_by_key(&u, |m| m.uid) else { continue };
                let seq = i as u32 + 1;
                let mut msg = Msg { meta: &metas[m], seq, recent, dir: &data_dir, content: None };
                if !content {
                    msg.content = Some(Content::default());
                }
                if msg.eval(&key).map_err(StoreError::Io)? {
                    hits.push(if uid { u } else { seq });
                }
            }
            Ok(hits)
        })
        .await;
    let hits = match r {
        Ok(h) => h,
        Err(e) => {
            crate::log_warn!("imap: SEARCH in mailbox {}: {e}", mailbox.0);
            return Ok(Reply::internal());
        }
    };
    let mut out = b"* SEARCH".to_vec();
    for h in hits {
        out.extend_from_slice(format!(" {h}").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    s.send(&out).await?;
    Ok(Reply::ok("SEARCH completed"))
}

/// Ranges of a sequence set with `*` = `last`, each as (low, high).
fn ranges(set: &SequenceSet, last: u32) -> Vec<(u32, u32)> {
    let v = |x: &SeqOrUid| match x {
        SeqOrUid::Value(n) => n.get(),
        SeqOrUid::Asterisk => last,
    };
    set.0
        .as_ref()
        .iter()
        .map(|s| match s {
            Sequence::Single(x) => (v(x), v(x)),
            Sequence::Range(a, b) => (v(a).min(v(b)), v(a).max(v(b))),
        })
        .collect()
}

fn lower(s: &[u8]) -> Vec<u8> {
    s.to_ascii_lowercase()
}

/// 00:00 UTC of a SEARCH date argument.
fn day_of(d: &imap_codec::imap_types::datetime::NaiveDate) -> Option<i64> {
    Some(d.as_ref().and_hms_opt(0, 0, 0)?.and_utc().timestamp())
}

fn convert(k: &SearchKey<'_>, last_seq: u32, last_uid: u32, depth: usize) -> Option<Key> {
    if depth > MAX_DEPTH {
        return None;
    }
    let sub = |k: &SearchKey<'_>| convert(k, last_seq, last_uid, depth + 1).map(Box::new);
    let hdr = |name: &str, v: &[u8]| Key::Header(name.as_bytes().to_vec(), lower(v));
    use SearchKey as S;
    Some(match k {
        S::And(v) => Key::And(v.as_ref().iter().map(|k| convert(k, last_seq, last_uid, depth + 1)).collect::<Option<Vec<_>>>()?),
        S::Or(a, b) => Key::Or(sub(a)?, sub(b)?),
        S::Not(a) => Key::Not(sub(a)?),
        S::All => Key::Const(true),
        S::SequenceSet(set) => Key::Seq(ranges(set, last_seq)),
        S::Uid(set) => Key::Uid(ranges(set, last_uid)),
        S::Answered => Key::Flag(Flags::ANSWERED, true),
        S::Unanswered => Key::Flag(Flags::ANSWERED, false),
        S::Deleted => Key::Flag(Flags::DELETED, true),
        S::Undeleted => Key::Flag(Flags::DELETED, false),
        S::Draft => Key::Flag(Flags::DRAFT, true),
        S::Undraft => Key::Flag(Flags::DRAFT, false),
        S::Flagged => Key::Flag(Flags::FLAGGED, true),
        S::Unflagged => Key::Flag(Flags::FLAGGED, false),
        S::Seen => Key::Flag(Flags::SEEN, true),
        S::Unseen => Key::Flag(Flags::SEEN, false),
        // Keywords are never stored.
        S::Keyword(_) => Key::Const(false),
        S::Unkeyword(_) => Key::Const(true),
        S::Recent => Key::Recent,
        S::Old => Key::Not(Box::new(Key::Recent)),
        S::New => Key::And(vec![Key::Recent, Key::Flag(Flags::SEEN, false)]),
        S::Larger(n) => Key::Larger(u64::from(*n)),
        S::Smaller(n) => Key::Smaller(u64::from(*n)),
        S::Before(d) => Key::Before(day_of(d)?),
        S::On(d) => Key::On(day_of(d)?),
        S::Since(d) => Key::Since(day_of(d)?),
        S::SentBefore(d) => Key::SentBefore(day_of(d)?),
        S::SentOn(d) => Key::SentOn(day_of(d)?),
        S::SentSince(d) => Key::SentSince(day_of(d)?),
        S::From(v) => hdr("from", v.as_ref()),
        S::To(v) => hdr("to", v.as_ref()),
        S::Cc(v) => hdr("cc", v.as_ref()),
        S::Bcc(v) => hdr("bcc", v.as_ref()),
        S::Subject(v) => hdr("subject", v.as_ref()),
        S::Header(name, v) => Key::Header(lower(name.as_ref()), lower(v.as_ref())),
        S::Body(v) => Key::Body(lower(v.as_ref())),
        S::Text(v) => Key::Text(lower(v.as_ref())),
    })
}

/// What the header and body keys look at, built once per message on first use.
#[derive(Default)]
struct Content {
    /// (lowercase field name, lowercased decoded value) of every top-level header field.
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// The raw header block, lowercased (TEXT also matches field names and raw text).
    head: Vec<u8>,
    /// The Date header's calendar day, 00:00 UTC.
    sent_day: Option<i64>,
    /// Decoded text of every text part, nested messages included, lowercased; None until needed.
    body: Option<Vec<u8>>,
}

struct Msg<'a> {
    meta: &'a MessageMeta,
    seq: u32,
    recent: bool,
    dir: &'a Path,
    content: Option<Content>,
}

fn parse(raw: &[u8]) -> Option<mail_parser::Message<'_>> {
    MessageParser::new().max_depth(20).max_parts(1000).max_encoded_nesting(2).parse(raw)
}

/// The header block of the blob at `path`, through the blank line (all of it when there is none),
/// read in 8 KiB steps.
fn read_head(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    loop {
        // An LF in the last two bytes read may start the blank line: look at them again.
        let from = buf.len().saturating_sub(2);
        let n = (&mut f).take(8 * 1024).read_to_end(&mut buf)?;
        if let Some(end) = header_len_from(&buf, from) {
            buf.truncate(end);
            return Ok(buf);
        }
        if n == 0 {
            return Ok(buf);
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// A header value as text: RFC 2047 encoded words decoded, lines unfolded.
fn header_text(raw_value: &[u8]) -> Vec<u8> {
    let parsed = HeaderForm::Text.parse(raw_value);
    match parsed.value() {
        HeaderValue::Text(t) => lower(t.as_bytes()),
        _ => lower(String::from_utf8_lossy(raw_value).trim().as_bytes()),
    }
}

fn sent_day(d: DateTime) -> i64 {
    DateTime { hour: 0, minute: 0, second: 0, tz_before_gmt: false, tz_hour: 0, tz_minute: 0, ..d }.to_timestamp()
}

/// Header fields and decoded text of a nested message, then its parts.
fn body_text(part: MessagePart<'_>, out: &mut Vec<u8>, depth: usize) {
    if depth > 20 {
        return;
    }
    if part.is_multipart() {
        for c in part.children() {
            body_text(c, out, depth + 1);
        }
    } else if let Some(inner) = part.nested() {
        message_text(inner, out, depth + 1);
    } else if let Some(t) = part.text() {
        out.extend_from_slice(t.as_bytes());
        out.push(b'\n');
    }
}

fn message_text(m: MessageRef<'_>, out: &mut Vec<u8>, depth: usize) {
    for h in m.headers().iter() {
        out.extend_from_slice(h.raw_name().as_bytes());
        out.extend_from_slice(b": ");
        let parsed = HeaderForm::Text.parse(h.raw_value());
        if let HeaderValue::Text(t) = parsed.value() {
            out.extend_from_slice(t.as_bytes());
        }
        out.push(b'\n');
    }
    body_text(m.root_part(), out, depth);
}

impl Msg<'_> {
    fn path(&self) -> PathBuf {
        self.dir.join(&self.meta.blob)
    }

    /// Header keys read only the header block, so FROM / SUBJECT / SENT* on a 25 MiB message
    /// cost a few KiB; the whole blob is read only for BODY and TEXT.
    fn content(&mut self) -> io::Result<&mut Content> {
        if self.content.is_none() {
            let head = read_head(&self.path())?;
            let mut c = Content::default();
            if let Some(m) = parse(&head) {
                let root = m.root();
                for h in root.headers().iter() {
                    c.headers.push((lower(h.raw_name().as_bytes()), header_text(h.raw_value())));
                }
                c.sent_day = root.date().filter(|d| d.is_valid()).map(sent_day);
            }
            c.head = lower(&head);
            self.content = Some(c);
        }
        Ok(self.content.get_or_insert_with(Content::default))
    }

    fn body(&mut self) -> io::Result<&[u8]> {
        let path = self.path();
        let c = self.content()?;
        if c.body.is_none() {
            let raw = std::fs::read(path)?;
            let mut out = Vec::new();
            if let Some(m) = parse(&raw) {
                body_text(m.root().root_part(), &mut out, 0);
            }
            out.make_ascii_lowercase();
            out.shrink_to_fit();
            c.body = Some(out);
        }
        Ok(c.body.as_deref().unwrap_or_default())
    }

    fn eval(&mut self, k: &Key) -> io::Result<bool> {
        let m = self.meta;
        Ok(match k {
            Key::And(v) => {
                for k in v {
                    if !self.eval(k)? {
                        return Ok(false);
                    }
                }
                true
            }
            Key::Or(a, b) => self.eval(a)? || self.eval(b)?,
            Key::Not(a) => !self.eval(a)?,
            Key::Const(b) => *b,
            Key::Seq(r) => r.iter().any(|&(lo, hi)| (lo..=hi).contains(&self.seq)),
            Key::Uid(r) => r.iter().any(|&(lo, hi)| (lo..=hi).contains(&m.uid)),
            Key::Flag(f, want) => m.flags.contains(*f) == *want,
            Key::Recent => self.recent,
            Key::Larger(n) => m.size > *n,
            Key::Smaller(n) => m.size < *n,
            Key::Before(d) => crate::time::imap_day(m.internal_date) < *d,
            Key::On(d) => crate::time::imap_day(m.internal_date) == *d,
            Key::Since(d) => crate::time::imap_day(m.internal_date) >= *d,
            Key::SentBefore(d) => self.content()?.sent_day.is_some_and(|s| s < *d),
            Key::SentOn(d) => self.content()?.sent_day.is_some_and(|s| s == *d),
            Key::SentSince(d) => self.content()?.sent_day.is_some_and(|s| s >= *d),
            Key::Header(name, v) => self.content()?.headers.iter().any(|(n, t)| n == name && contains(t, v)),
            Key::Body(v) => contains(self.body()?, v),
            Key::Text(v) => {
                let c = self.content()?;
                contains(&c.head, v) || c.headers.iter().any(|(_, t)| contains(t, v)) || contains(self.body()?, v)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_text_decodes_encoded_words() {
        assert_eq!(header_text(b" =?ISO-8859-2?Q?=A9tefan?= <s@example.si>\r\n"), "Štefan <s@example.si>".as_bytes());
        assert_eq!(header_text(b" =?UTF-8?B?xaB1bW5pa2kgxI3Eh8W+?=\r\n"), "Šumniki čćž".as_bytes());
        assert_eq!(header_text(b" Quarterly\r\n report\r\n"), b"quarterly report");
    }

    /// imap-codec 1.0 stops at 9 nested levels (docs/DEVIATIONS.md); deeper commands get BAD.
    #[test]
    fn nesting_limit_is_nine() {
        use imap_codec::CommandCodec;
        use imap_codec::decode::Decoder;
        let cmd = |n: usize| format!("A SEARCH {}{}\r\n", "NOT ".repeat(n), "SEEN");
        let ok = |n: usize| {
            let c = cmd(n);
            matches!(CommandCodec::default().decode(c.as_bytes()), Ok((rest, _)) if rest.is_empty())
        };
        let depth = (0..20).take_while(|&n| ok(n)).count();
        // 8 NOTs around a key = 9 levels pass; 9 NOTs (10 levels) fail.
        assert_eq!(depth, 9, "parser accepts up to {} NOTs", depth.saturating_sub(1));
        assert!(!ok(depth + 5));
    }

    #[test]
    fn substring() {
        assert!(contains(b"abc", b""));
        assert!(contains(b"abc", b"bc"));
        assert!(!contains(b"ab", b"abc"));
    }
}
