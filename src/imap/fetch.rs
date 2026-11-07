//! FETCH / UID FETCH: sequence sets, data items and macros, sections and partials, and `\Seen`
//! on non-PEEK body fetches (RFC 3501 6.4.5 and 7.4.2).
//!
//! Memory: whole-message ranges (BODY[], BODY[TEXT], RFC822, RFC822.TEXT and their partials) are
//! streamed from the blob in chunks; headers are read only up to the blank line; MIME parts,
//! BODY and BODYSTRUCTURE read the blob once per message and parse it with mail-parser, and
//! everything is dropped when the message's response line is written.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroU32;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

use imap_codec::imap_types::fetch::{MacroOrMessageDataItemNames, MessageDataItemName, Part, Section};
use imap_codec::imap_types::flag::{Flag, StoreResponse, StoreType};
use imap_codec::imap_types::sequence::{SeqOrUid, Sequence, SequenceSet};
use mail_parser::{MessageParser, MessagePart, MessageRef};

use super::bodystructure::{self as bs, header_len_from};
use super::session::{Reply, Session, State};
use super::wire;
use crate::store::{FlagOp, Flags, MessageMeta};

/// Blob bytes read per step when streaming a literal.
const CHUNK: usize = 128 * 1024;
/// Header bytes read per step while looking for the blank line.
const HEAD_STEP: usize = 8 * 1024;

pub(crate) async fn fetch(s: &mut Session, set: &SequenceSet, items: MacroOrMessageDataItemNames<'_>, uid: bool) -> io::Result<Reply> {
    let State::Selected(sel) = &s.state else {
        return Ok(Reply::no("No mailbox selected"));
    };
    let Some(targets) = resolve(set, &sel.uids, uid) else {
        return Ok(Reply::bad("Invalid message sequence number"));
    };
    let (mailbox, read_only) = (sel.mailbox, sel.read_only);
    let recent: Vec<bool> = targets.iter().map(|&(_, u)| sel.is_recent(u)).collect();

    let mac;
    let mut names: Vec<MessageDataItemName<'_>> = match items {
        MacroOrMessageDataItemNames::Macro(m) => {
            mac = m;
            mac.expand()
        }
        MacroOrMessageDataItemNames::MessageDataItemNames(v) => v,
    };
    if uid && !names.contains(&MessageDataItemName::Uid) {
        names.insert(0, MessageDataItemName::Uid);
    }
    if targets.is_empty() {
        return Ok(Reply::ok("FETCH completed"));
    }

    let mut metas = match s.blocking(move |st| st.messages(mailbox)).await {
        Ok(m) => m,
        Err(e) => {
            crate::log_warn!("imap: FETCH: reading mailbox {}: {e}", mailbox.0);
            return Ok(Reply::internal());
        }
    };

    // Non-PEEK body sections set \Seen first, so the FLAGS sent below already show it.
    let mut changed = BTreeSet::new();
    let sets_seen = names.iter().any(|n| matches!(n, MessageDataItemName::BodyExt { peek: false, .. } | MessageDataItemName::Rfc822 | MessageDataItemName::Rfc822Text));
    if sets_seen && !read_only {
        let unseen: Vec<u32> =
            targets.iter().filter_map(|&(_, u)| meta_of(&metas, u)).filter(|m| !m.flags.contains(Flags::SEEN)).map(|m| m.uid).collect();
        if !unseen.is_empty() {
            match s.blocking(move |st| st.store_flags(mailbox, &unseen, FlagOp::Add, Flags::SEEN)).await {
                Ok(updates) => {
                    for u in updates {
                        if let Ok(i) = metas.binary_search_by_key(&u.uid, |m| m.uid) {
                            metas[i].flags = u.flags;
                        }
                        changed.insert(u.uid);
                    }
                }
                Err(e) => {
                    crate::log_warn!("imap: FETCH: setting \\Seen in mailbox {}: {e}", mailbox.0);
                    return Ok(Reply::internal());
                }
            }
        }
    }
    let wants_flags = names.contains(&MessageDataItemName::Flags);

    let data_dir = s.store.data_dir().to_path_buf();
    for (n, &(seq, u)) in targets.iter().enumerate() {
        // A message expunged by another session after this one's uid list was read: skip it.
        let Some(meta) = meta_of(&metas, u) else { continue };
        let mut msg = Msg { path: data_dir.join(&meta.blob), size: meta.size, file: None, head: None, full: None };
        let mut out = format!("* {seq} FETCH (").into_bytes();
        let mut first = true;
        for name in &names {
            if !std::mem::take(&mut first) {
                out.push(b' ');
            }
            if let Err(e) = item(s, &mut out, &mut msg, meta, recent[n], name).await {
                // The response may be half written (a literal announced): the connection must go.
                crate::log_warn!("imap: FETCH: message uid {u} of mailbox {}: {e}", mailbox.0);
                return Err(e);
            }
        }
        if changed.contains(&u) && !wants_flags {
            out.push(b' ');
            flags(&mut out, meta.flags, recent[n]);
        }
        out.extend_from_slice(b")\r\n");
        s.send(&out).await?;
    }
    Ok(Reply::ok("FETCH completed"))
}

/// STORE / UID STORE (RFC 3501 6.4.6). Only `\Seen \Answered \Flagged \Draft` are kept;
/// `\Deleted`, keywords and extension flags are accepted and ignored (they are not in
/// PERMANENTFLAGS, RFC 3501 7.1), so nothing can mark mail for removal.
pub(crate) async fn store(s: &mut Session, set: &SequenceSet, kind: StoreType, response: StoreResponse, list: &[Flag<'_>], uid: bool) -> io::Result<Reply> {
    let State::Selected(sel) = &s.state else {
        return Ok(Reply::no("No mailbox selected"));
    };
    if sel.read_only {
        return Ok(Reply::no("[READ-ONLY] Mailbox is read-only"));
    }
    let Some(targets) = resolve(set, &sel.uids, uid) else {
        return Ok(Reply::bad("Invalid message sequence number"));
    };
    let mailbox = sel.mailbox;
    let recent: Vec<bool> = targets.iter().map(|&(_, u)| sel.is_recent(u)).collect();
    let mask = flag_mask(list);
    let op = match kind {
        StoreType::Add => FlagOp::Add,
        StoreType::Remove => FlagOp::Remove,
        StoreType::Replace => FlagOp::Replace,
    };
    if targets.is_empty() {
        return Ok(Reply::ok("STORE completed"));
    }
    let uids: Vec<u32> = targets.iter().map(|&(_, u)| u).collect();
    let updates = match s.blocking(move |st| st.store_flags(mailbox, &uids, op, mask)).await {
        Ok(u) => u,
        Err(e) => {
            crate::log_warn!("imap: STORE in mailbox {}: {e}", mailbox.0);
            return Ok(Reply::internal());
        }
    };
    if matches!(response, StoreResponse::Silent) {
        return Ok(Reply::ok("STORE completed"));
    }
    let mut out = Vec::new();
    for (n, &(seq, u)) in targets.iter().enumerate() {
        let Ok(i) = updates.binary_search_by_key(&u, |x| x.uid) else { continue };
        out.extend_from_slice(format!("* {seq} FETCH (").as_bytes());
        if uid {
            out.extend_from_slice(format!("UID {u} ").as_bytes());
        }
        flags(&mut out, updates[i].flags, recent[n]);
        out.extend_from_slice(b")\r\n");
    }
    s.send(&out).await?;
    Ok(Reply::ok("STORE completed"))
}

fn meta_of(metas: &[MessageMeta], uid: u32) -> Option<&MessageMeta> {
    metas.binary_search_by_key(&uid, |m| m.uid).ok().map(|i| &metas[i])
}

/// (sequence number, uid) of every message in `set`, ascending and without duplicates. None: a
/// sequence number past the last message (RFC 3501 9: BAD, `*` of an empty mailbox included).
/// UID sets never fail: uids that do not exist are left out.
pub(super) fn flag_mask(list:&[Flag])->Flags {
    let mut mask = Flags::empty();
    for f in list {
        mask = mask
            | match f {
                Flag::Seen => Flags::SEEN,
                Flag::Answered => Flags::ANSWERED,
                Flag::Flagged => Flags::FLAGGED,
                Flag::Deleted => Flags::DELETED,
                Flag::Draft => Flags::DRAFT,
                _ => Flags::empty(),
            };
    }
    mask
}

pub(super) fn resolve(set: &SequenceSet, uids: &[u32], by_uid: bool) -> Option<Vec<(u32, u32)>> {
    let last = if by_uid { uids.last().copied().unwrap_or(0) } else { uids.len() as u32 };
    let value = |x: &SeqOrUid| match x {
        SeqOrUid::Value(v) => v.get(),
        SeqOrUid::Asterisk => last,
    };
    let mut seqs = BTreeSet::new();
    for s in set.0.as_ref() {
        let (a, b) = match s {
            Sequence::Single(x) => (value(x), value(x)),
            Sequence::Range(x, y) => (value(x), value(y)),
        };
        let (lo, hi) = (a.min(b), a.max(b));
        if by_uid {
            let start = uids.partition_point(|&u| u < lo);
            let end = uids.partition_point(|&u| u <= hi);
            seqs.extend((start..end).map(|i| i as u32 + 1));
        } else {
            if lo == 0 || hi > last {
                return None;
            }
            seqs.extend(lo..=hi);
        }
    }
    Some(seqs.into_iter().map(|q| (q, uids[q as usize - 1])).collect())
}

/// `FLAGS (...)`. `\Deleted` is never shown (the server ignores it).
fn flags(out: &mut Vec<u8>, f: Flags, recent: bool) {
    let mut names = Vec::new();
    for (flag, name) in [
        (Flags::SEEN, "\\Seen"),
        (Flags::ANSWERED, "\\Answered"),
        (Flags::FLAGGED, "\\Flagged"),
        (Flags::DELETED, "\\Deleted"),
        (Flags::DRAFT, "\\Draft"),
    ] {
        if f.contains(flag) {
            names.push(name);
        }
    }
    if recent {
        names.push("\\Recent");
    }
    out.extend_from_slice(format!("FLAGS ({})", names.join(" ")).as_bytes());
}

/// One message's blob, read lazily: the header block or the whole file, at most once each.
struct Msg {
    path: PathBuf,
    size: u64,
    file: Option<Arc<File>>,
    head: Option<Vec<u8>>,
    full: Option<Arc<Vec<u8>>>,
}

async fn off_thread<T: Send + 'static>(f: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(io::Error::other)?
}

impl Msg {
    async fn file(&mut self) -> io::Result<Arc<File>> {
        if let Some(f) = &self.file {
            return Ok(f.clone());
        }
        let path = self.path.clone();
        let f = Arc::new(off_thread(move || File::open(path)).await?);
        self.file = Some(f.clone());
        Ok(f)
    }

    /// The header block, through the blank line (the whole blob when it has none).
    async fn head(&mut self) -> io::Result<&[u8]> {
        if self.head.is_none() {
            let h = match &self.full {
                Some(full) => bs::split(full).0.to_vec(),
                None => {
                    let f = self.file().await?;
                    off_thread(move || {
                        let mut buf = Vec::new();
                        let mut r = &*f;
                        loop {
                            // An LF in the last two bytes read may start a blank line: look again.
                            let from = buf.len().saturating_sub(2);
                            let n = r.by_ref().take(HEAD_STEP as u64).read_to_end(&mut buf)?;
                            if let Some(end) = header_len_from(&buf, from) {
                                buf.truncate(end);
                                break;
                            }
                            if n == 0 {
                                break;
                            }
                        }
                        buf.shrink_to_fit();
                        Ok(buf)
                    })
                    .await?
                }
            };
            self.head = Some(h);
        }
        Ok(self.head.as_deref().unwrap_or_default())
    }

    async fn full(&mut self) -> io::Result<Arc<Vec<u8>>> {
        if let Some(f) = &self.full {
            return Ok(f.clone());
        }
        let path = self.path.clone();
        let full = Arc::new(off_thread(move || std::fs::read(path)).await?);
        self.full = Some(full.clone());
        Ok(full)
    }
}

/// Write one data item (name and value) to `out`; large values are streamed straight to the
/// client after flushing `out`.
async fn item(s: &mut Session, out: &mut Vec<u8>, msg: &mut Msg, meta: &MessageMeta, recent: bool, name: &MessageDataItemName<'_>) -> io::Result<()> {
    use MessageDataItemName as N;
    match name {
        N::Uid => out.extend_from_slice(format!("UID {}", meta.uid).as_bytes()),
        N::Flags => flags(out, meta.flags, recent),
        N::InternalDate => out.extend_from_slice(format!("INTERNALDATE \"{}\"", crate::time::format_imap_datetime(meta.internal_date)).as_bytes()),
        N::Rfc822Size => out.extend_from_slice(format!("RFC822.SIZE {}", meta.size).as_bytes()),
        N::Envelope => {
            out.extend_from_slice(b"ENVELOPE ");
            bs::envelope(out, msg.head().await?);
        }
        N::Body | N::BodyStructure => {
            let ext = matches!(name, N::BodyStructure);
            out.extend_from_slice(if ext { b"BODYSTRUCTURE " } else { b"BODY " });
            let full = msg.full().await?;
            let (_, text) = bs::split(&full);
            match parse(&full) {
                Some(m) => bs::body(out, m.root(), Some(text), ext),
                None => out.extend_from_slice(format!("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {} {})", text.len(), bs::lines(text)).as_bytes()),
            }
        }
        N::Rfc822Header => {
            out.extend_from_slice(b"RFC822.HEADER ");
            wire::literal(out, msg.head().await?);
        }
        N::Rfc822 => {
            out.extend_from_slice(b"RFC822 ");
            let size = msg.size;
            stream(s, out, msg, 0, size).await?;
        }
        N::Rfc822Text => {
            out.extend_from_slice(b"RFC822.TEXT ");
            let h = msg.head().await?.len() as u64;
            let len = msg.size.saturating_sub(h);
            stream(s, out, msg, h, len).await?;
        }
        N::BodyExt { section, partial, .. } => {
            out.extend_from_slice(b"BODY[");
            if let Some(sec) = section {
                section_name(out, sec);
            }
            out.push(b']');
            let partial = partial.map(|(o, l)| (u64::from(o), u64::from(l.get())));
            if let Some((o, _)) = partial {
                out.extend_from_slice(format!("<{o}>").as_bytes());
            }
            out.push(b' ');
            body_section(s, out, msg, section.as_ref(), partial).await?;
        }
        // BINARY and friends are not decoded by imap-codec without their feature flags.
        #[allow(unreachable_patterns)]
        _ => out.extend_from_slice(b"NIL NIL"),
    }
    Ok(())
}

/// The section spec as the client wrote it (field names echoed as given).
fn section_name(out: &mut Vec<u8>, sec: &Section<'_>) {
    let part = |out: &mut Vec<u8>, p: &Part, dot: bool| {
        let nums: Vec<String> = p.0.as_ref().iter().map(|n| n.to_string()).collect();
        out.extend_from_slice(nums.join(".").as_bytes());
        if dot {
            out.push(b'.');
        }
    };
    let names = |out: &mut Vec<u8>, list: &[imap_codec::imap_types::core::AString<'_>]| {
        out.extend_from_slice(b" (");
        for (i, f) in list.iter().enumerate() {
            if i > 0 {
                out.push(b' ');
            }
            wire::astring(out, f.as_ref());
        }
        out.push(b')');
    };
    match sec {
        Section::Part(p) => part(out, p, false),
        Section::Header(p) => {
            if let Some(p) = p {
                part(out, p, true);
            }
            out.extend_from_slice(b"HEADER");
        }
        Section::HeaderFields(p, list) | Section::HeaderFieldsNot(p, list) => {
            if let Some(p) = p {
                part(out, p, true);
            }
            out.extend_from_slice(if matches!(sec, Section::HeaderFields(..)) { b"HEADER.FIELDS" } else { b"HEADER.FIELDS.NOT" });
            names(out, list.as_ref());
        }
        Section::Text(p) => {
            if let Some(p) = p {
                part(out, p, true);
            }
            out.extend_from_slice(b"TEXT");
        }
        Section::Mime(p) => {
            part(out, p, true);
            out.extend_from_slice(b"MIME");
        }
    }
}

fn parse(raw: &[u8]) -> Option<mail_parser::Message<'_>> {
    MessageParser::new().max_depth(20).max_parts(1000).max_encoded_nesting(2).parse(raw)
}

/// `[from, to)` of a value of length `len` after the partial `<o.l>`.
fn clamp(len: u64, partial: Option<(u64, u64)>) -> (u64, u64) {
    match partial {
        None => (0, len),
        Some((o, l)) => {
            let from = o.min(len);
            (from, o.saturating_add(l).min(len))
        }
    }
}

fn literal_part(out: &mut Vec<u8>, v: &[u8], partial: Option<(u64, u64)>) {
    let (a, b) = clamp(v.len() as u64, partial);
    wire::literal(out, &v[a as usize..b as usize]);
}

async fn body_section(s: &mut Session, out: &mut Vec<u8>, msg: &mut Msg, section: Option<&Section<'_>>, partial: Option<(u64, u64)>) -> io::Result<()> {
    match section {
        None => {
            let (a, b) = clamp(msg.size, partial);
            stream(s, out, msg, a, b - a).await
        }
        Some(Section::Text(None)) => {
            let h = msg.head().await?.len() as u64;
            let (a, b) = clamp(msg.size.saturating_sub(h), partial);
            stream(s, out, msg, h + a, b - a).await
        }
        Some(Section::Header(None)) => {
            literal_part(out, msg.head().await?, partial);
            Ok(())
        }
        Some(Section::HeaderFields(None, list)) | Some(Section::HeaderFieldsNot(None, list)) => {
            let not = matches!(section, Some(Section::HeaderFieldsNot(..)));
            let names: Vec<&[u8]> = list.as_ref().iter().map(|a| a.as_ref()).collect();
            let v = bs::filter_fields(msg.head().await?, &names, not);
            literal_part(out, &v, partial);
            Ok(())
        }
        Some(sec) => {
            let full = msg.full().await?;
            let v = part_section(&full, sec);
            match v {
                Some(v) => literal_part(out, &v, partial),
                None => out.extend_from_slice(b"NIL"),
            }
            Ok(())
        }
    }
}

/// A section below the top level (a part number, or a part's MIME / HEADER / TEXT); None when the
/// part does not exist.
fn part_section(full: &[u8], sec: &Section<'_>) -> Option<Vec<u8>> {
    let (top_head, top_text) = bs::split(full);
    let m = parse(full)?;
    let root = m.root();
    // HEADER / TEXT / HEADER.FIELDS of part p: p must be a message/rfc822 part.
    let nested_split = |p: &Part| -> Option<(Vec<u8>, Vec<u8>)> {
        let part = find_part(root, p.0.as_ref())?;
        let n = part.nested()?;
        let (h, t) = bs::split(n.raw());
        Some((h.to_vec(), t.to_vec()))
    };
    match sec {
        Section::Part(p) => {
            let path = p.0.as_ref();
            if path.len() == 1 && path[0].get() == 1 && !root.root_part().is_multipart() {
                return Some(top_text.to_vec());
            }
            Some(find_part(root, path)?.raw_body().to_vec())
        }
        Section::Mime(p) => Some(find_part(root, p.0.as_ref())?.raw_headers().to_vec()),
        Section::Header(Some(p)) => nested_split(p).map(|x| x.0),
        Section::Text(Some(p)) => nested_split(p).map(|x| x.1),
        Section::HeaderFields(Some(p), list) | Section::HeaderFieldsNot(Some(p), list) => {
            let not = matches!(sec, Section::HeaderFieldsNot(..));
            let names: Vec<&[u8]> = list.as_ref().iter().map(|a| a.as_ref()).collect();
            nested_split(p).map(|(h, _)| bs::filter_fields(&h, &names, not))
        }
        // Top-level sections are served without parsing; kept for completeness.
        Section::Header(None) => Some(top_head.to_vec()),
        Section::Text(None) => Some(top_text.to_vec()),
        Section::HeaderFields(None, list) | Section::HeaderFieldsNot(None, list) => {
            let not = matches!(sec, Section::HeaderFieldsNot(..));
            let names: Vec<&[u8]> = list.as_ref().iter().map(|a| a.as_ref()).collect();
            Some(bs::filter_fields(top_head, &names, not))
        }
    }
}

/// Part `path` of message `m` (RFC 3501 6.4.5): in a multipart, part n is its nth child; a
/// non-multipart message has only part 1, its body; below a message/rfc822 part the numbering
/// continues in the encapsulated message.
fn find_part<'m>(m: MessageRef<'m>, path: &[NonZeroU32]) -> Option<MessagePart<'m>> {
    let (first, rest) = path.split_first()?;
    let mut p = child_of_message(m, first.get() as usize)?;
    for n in rest {
        let n = n.get() as usize;
        p = if p.is_multipart() {
            p.children().nth(n - 1)?
        } else {
            let inner = p.nested()?;
            child_of_message(inner, n)?
        };
    }
    Some(p)
}

fn child_of_message(m: MessageRef<'_>, n: usize) -> Option<MessagePart<'_>> {
    let root = m.root_part();
    if root.is_multipart() {
        root.children().nth(n - 1)
    } else {
        (n == 1).then_some(root)
    }
}

/// `{len}` and `len` bytes of the blob from `offset`, NUL replaced, read and sent in chunks.
async fn stream(s: &mut Session, out: &mut Vec<u8>, msg: &mut Msg, offset: u64, len: u64) -> io::Result<()> {
    out.extend_from_slice(format!("{{{len}}}\r\n").as_bytes());
    if len == 0 {
        return Ok(());
    }
    let file = msg.file().await?;
    s.send(out).await?;
    out.clear();
    let (mut off, end) = (offset, offset + len);
    while off < end {
        let n = (end - off).min(CHUNK as u64) as usize;
        let f = file.clone();
        let mut buf = off_thread(move || {
            let mut b = vec![0; n];
            f.read_exact_at(&mut b, off)?;
            Ok(b)
        })
        .await?;
        wire::replace_nul(&mut buf);
        s.send(&buf).await?;
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_codec::imap_types::core::NonEmptyVec;

    fn set(v: Vec<Sequence>) -> SequenceSet {
        SequenceSet(NonEmptyVec::try_from(v).unwrap())
    }
    fn n(x: u32) -> SeqOrUid {
        SeqOrUid::Value(NonZeroU32::new(x).unwrap())
    }

    #[test]
    fn sequence_sets() {
        let uids = [10, 20, 30];
        let r = |v, by_uid| resolve(&set(v), &uids, by_uid);
        assert_eq!(r(vec![Sequence::Range(n(1), SeqOrUid::Asterisk)], false), Some(vec![(1, 10), (2, 20), (3, 30)]));
        assert_eq!(r(vec![Sequence::Single(n(4))], false), None);
        assert_eq!(r(vec![Sequence::Range(n(15), n(25))], true), Some(vec![(2, 20)]));
        assert_eq!(r(vec![Sequence::Range(n(100), SeqOrUid::Asterisk)], true), Some(vec![(3, 30)]));
        assert_eq!(resolve(&set(vec![Sequence::Single(SeqOrUid::Asterisk)]), &[], false), None);
        assert_eq!(resolve(&set(vec![Sequence::Single(SeqOrUid::Asterisk)]), &[], true), Some(vec![]));
    }

    #[test]
    fn partial_clamp() {
        assert_eq!(clamp(10, None), (0, 10));
        assert_eq!(clamp(10, Some((5, 100))), (5, 10));
        assert_eq!(clamp(10, Some((50, 1))), (10, 10));
    }
}
