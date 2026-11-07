//! ENVELOPE, BODY and BODYSTRUCTURE (RFC 3501 sections 7.4.2 and 9), built per request from the
//! raw header fields of the message and its parts. mail-parser supplies the MIME tree and the raw
//! slices; every string in the output comes from the raw headers (unfolded, otherwise as written:
//! encoded words stay encoded, Content-ID keeps its angle brackets).

use mail_parser::{MessagePart, MessageRef};

use super::wire;

// ---- header blocks ---------------------------------------------------------------------------

/// Length of the header block of `raw`, through the first blank line (CRLF or bare LF). No blank
/// line: the whole message is header and the text is empty.
pub(crate) fn header_len(raw: &[u8]) -> Option<usize> {
    header_len_from(raw, 0)
}

/// `header_len`, looking only at line ends from `from` on (incremental reads).
pub(crate) fn header_len_from(raw: &[u8], from: usize) -> Option<usize> {
    if from == 0 && raw.starts_with(b"\r\n") {
        return Some(2);
    }
    if from == 0 && raw.starts_with(b"\n") {
        return Some(1);
    }
    let mut i = from.min(raw.len());
    while let Some(p) = raw[i..].iter().position(|&b| b == b'\n') {
        let lf = i + p;
        match raw.get(lf + 1) {
            Some(b'\n') => return Some(lf + 2),
            Some(b'\r') if raw.get(lf + 2) == Some(&b'\n') => return Some(lf + 3),
            _ => i = lf + 1,
        }
    }
    None
}

/// (header block, text) of a message.
pub(crate) fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    let n = header_len(raw).unwrap_or(raw.len());
    raw.split_at(n)
}

/// One header field: its name, the raw field (continuation lines and line end included) and the
/// raw value after the colon.
pub(crate) struct Field<'a> {
    pub name: &'a [u8],
    pub raw: &'a [u8],
    pub value: &'a [u8],
}

/// The fields of a header block, in order, up to the blank line. Lines without a colon are skipped.
pub(crate) fn fields(block: &[u8]) -> impl Iterator<Item = Field<'_>> {
    let mut pos = 0;
    std::iter::from_fn(move || {
        loop {
            let rest = block.get(pos..).filter(|r| !r.is_empty())?;
            if rest[0] == b'\n' || rest.starts_with(b"\r\n") {
                return None;
            }
            let mut end = pos;
            loop {
                match block[end..].iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        end += i + 1;
                        if !matches!(block.get(end), Some(b' ' | b'\t')) {
                            break;
                        }
                    }
                    None => {
                        end = block.len();
                        break;
                    }
                }
            }
            let raw = &block[pos..end];
            pos = end;
            if let Some(c) = raw.iter().position(|&b| b == b':') {
                return Some(Field { name: trim(&raw[..c]), raw, value: &raw[c + 1..] });
            }
        }
    })
}

/// The unfolded, trimmed value of the first field called `name`.
pub(crate) fn header_value(block: &[u8], name: &str) -> Option<Vec<u8>> {
    fields(block).find(|f| f.name.eq_ignore_ascii_case(name.as_bytes())).map(|f| unfold(f.value))
}

/// Remove the CR and LF of folding, then surrounding white space.
pub(crate) fn unfold(v: &[u8]) -> Vec<u8> {
    let v: Vec<u8> = v.iter().copied().filter(|&b| b != b'\r' && b != b'\n').collect();
    trim(&v).to_vec()
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(v.len());
    let e = v.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(s, |e| e + 1);
    &v[s..e]
}

/// The fields of `block` whose name is (or, with `not`, is not) in `names`, raw and in message
/// order, followed by the blank line (RFC 3501 6.4.5 HEADER.FIELDS / HEADER.FIELDS.NOT).
pub(crate) fn filter_fields(block: &[u8], names: &[&[u8]], not: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields(block) {
        if names.iter().any(|n| n.eq_ignore_ascii_case(f.name)) != not {
            out.extend_from_slice(f.raw);
            if !f.raw.ends_with(b"\n") {
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Count of LF bytes: the body-fld-lines of RFC 3501.
pub(crate) fn lines(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

// ---- ENVELOPE --------------------------------------------------------------------------------

/// `(date subject from sender reply-to to cc bcc in-reply-to message-id)` of a header block.
pub(crate) fn envelope(out: &mut Vec<u8>, head: &[u8]) {
    let get = |n: &str| header_value(head, n);
    let addrs = |n: &str| get(n).map(|v| parse_addresses(&v)).filter(|l| !l.is_empty());
    out.push(b'(');
    wire::nstring(out, get("Date").as_deref());
    out.push(b' ');
    wire::nstring(out, get("Subject").as_deref());
    let from = addrs("From");
    let sender = addrs("Sender").or_else(|| from.clone());
    let reply_to = addrs("Reply-To").or_else(|| from.clone());
    for list in [&from, &sender, &reply_to, &addrs("To"), &addrs("Cc"), &addrs("Bcc")] {
        out.push(b' ');
        address_list(out, list.as_deref());
    }
    out.push(b' ');
    wire::nstring(out, get("In-Reply-To").as_deref());
    out.push(b' ');
    wire::nstring(out, get("Message-ID").as_deref());
    out.push(b')');
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Addr {
    Mailbox { name: Option<Vec<u8>>, mailbox: Vec<u8>, host: Option<Vec<u8>> },
    GroupStart(Vec<u8>),
    GroupEnd,
}

fn address_list(out: &mut Vec<u8>, list: Option<&[Addr]>) {
    let Some(list) = list else {
        out.extend_from_slice(b"NIL");
        return;
    };
    out.push(b'(');
    for a in list {
        match a {
            Addr::Mailbox { name, mailbox, host } => {
                out.push(b'(');
                wire::nstring(out, name.as_deref());
                out.extend_from_slice(b" NIL ");
                wire::string(out, mailbox);
                out.push(b' ');
                wire::nstring(out, host.as_deref());
                out.push(b')');
            }
            Addr::GroupStart(name) => {
                out.extend_from_slice(b"(NIL NIL ");
                wire::string(out, name);
                out.extend_from_slice(b" NIL)");
            }
            Addr::GroupEnd => out.extend_from_slice(b"(NIL NIL NIL NIL)"),
        }
    }
    out.push(b')');
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Word(Vec<u8>),
    Quoted(Vec<u8>),
    DomainLit(Vec<u8>),
    Sp(u8),
}

/// RFC 5322 lexer: atoms (dots allowed, as obs-phrase does), quoted strings, domain literals and
/// the specials `<>,:;@`. White space and comments are dropped.
fn lex(s: &[u8]) -> Vec<Tok> {
    let mut t = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                let mut depth = 0;
                while i < s.len() {
                    match s[i] {
                        b'\\' => i += 1,
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'"' => {
                let mut v = Vec::new();
                i += 1;
                while i < s.len() && s[i] != b'"' {
                    if s[i] == b'\\' && i + 1 < s.len() {
                        i += 1;
                    }
                    v.push(s[i]);
                    i += 1;
                }
                i += 1;
                t.push(Tok::Quoted(v));
            }
            b'[' => {
                let e = s[i..].iter().position(|&b| b == b']').map_or(s.len(), |p| i + p + 1);
                t.push(Tok::DomainLit(s[i..e].to_vec()));
                i = e;
            }
            b'<' | b'>' | b',' | b':' | b';' | b'@' => {
                t.push(Tok::Sp(c));
                i += 1;
            }
            _ => {
                let st = i;
                while i < s.len() && !b" \t\r\n()\"[<>,:;@".contains(&s[i]) {
                    i += 1;
                }
                t.push(Tok::Word(s[st..i].to_vec()));
            }
        }
    }
    t
}

fn is_sp(t: Option<&Tok>, set: &[u8]) -> bool {
    matches!(t, Some(Tok::Sp(c)) if set.contains(c))
}

/// An address list with groups (RFC 5322 3.4), leniently: anything unparsable is dropped.
fn parse_addresses(v: &[u8]) -> Vec<Addr> {
    let t = lex(v);
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if is_sp(t.get(i), b",;>") {
            i += 1;
            continue;
        }
        let j = (i..t.len()).find(|&k| is_sp(t.get(k), b":<@,;")).unwrap_or(t.len());
        if is_sp(t.get(j), b":") {
            out.push(Addr::GroupStart(phrase(&t[i..j]).unwrap_or_default()));
            i = j + 1;
            while i < t.len() && !is_sp(t.get(i), b";") {
                if is_sp(t.get(i), b",") {
                    i += 1;
                    continue;
                }
                if let Some(a) = mailbox(&t, &mut i) {
                    out.push(a);
                }
            }
            i += 1;
            out.push(Addr::GroupEnd);
        } else if let Some(a) = mailbox(&t, &mut i) {
            out.push(a);
        }
    }
    out
}

/// A name-addr or addr-spec starting at `t[*i]`; advances past it.
fn mailbox(t: &[Tok], i: &mut usize) -> Option<Addr> {
    let start = *i;
    let k = (start..t.len()).find(|&k| is_sp(t.get(k), b",;<")).unwrap_or(t.len());
    let (name, spec) = if is_sp(t.get(k), b"<") {
        let e = (k + 1..t.len()).find(|&e| is_sp(t.get(e), b">,;")).unwrap_or(t.len());
        *i = if is_sp(t.get(e), b">") { e + 1 } else { e };
        let mut spec = &t[k + 1..e];
        // obs-route: "<@a,@b:user@host>"
        if let Some(c) = spec.iter().rposition(|x| *x == Tok::Sp(b':')) {
            spec = &spec[c + 1..];
        }
        (phrase(&t[start..k]), spec)
    } else {
        *i = k.max(start + 1);
        (None, &t[start..k])
    };
    let at = spec.iter().rposition(|x| *x == Tok::Sp(b'@'));
    let text = |ts: &[Tok]| -> Vec<u8> {
        let mut v = Vec::new();
        for x in ts {
            match x {
                Tok::Word(w) | Tok::Quoted(w) | Tok::DomainLit(w) => v.extend_from_slice(w),
                Tok::Sp(c) => v.push(*c),
            }
        }
        v
    };
    let (mailbox, host) = match at {
        Some(a) => (text(&spec[..a]), Some(text(&spec[a + 1..]))),
        None => (text(spec), None),
    };
    if mailbox.is_empty() && host.as_ref().is_none_or(|h| h.is_empty()) {
        return None;
    }
    // A bare word without a domain would read as a group start (host NIL): mark it like Dovecot.
    let host = host.filter(|h| !h.is_empty()).or_else(|| Some(b"MISSING_DOMAIN".to_vec()));
    Some(Addr::Mailbox { name, mailbox, host })
}

/// Display-name words joined by one space; None when empty.
fn phrase(t: &[Tok]) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    for x in t {
        let w = match x {
            Tok::Word(w) | Tok::Quoted(w) | Tok::DomainLit(w) => w,
            Tok::Sp(_) => continue,
        };
        if !v.is_empty() {
            v.push(b' ');
        }
        v.extend_from_slice(w);
    }
    (!v.is_empty()).then_some(v)
}

// ---- BODY / BODYSTRUCTURE --------------------------------------------------------------------

/// A Content-Type or Content-Disposition value: the main token and its parameters (names as
/// written, values unquoted).
struct Typed {
    main: Vec<u8>,
    params: Vec<(Vec<u8>, Vec<u8>)>,
}

fn parse_typed(v: &[u8]) -> Typed {
    let semi = v.iter().position(|&b| b == b';').unwrap_or(v.len());
    let main = trim(&v[..semi]).to_vec();
    let mut params = Vec::new();
    let mut i = semi;
    while i < v.len() {
        while i < v.len() && (v[i] == b';' || v[i].is_ascii_whitespace()) {
            i += 1;
        }
        let st = i;
        while i < v.len() && v[i] != b'=' && v[i] != b';' {
            i += 1;
        }
        let name = trim(&v[st..i]).to_vec();
        if i >= v.len() || v[i] == b';' {
            continue;
        }
        i += 1; // '='
        while i < v.len() && v[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut val = Vec::new();
        if v.get(i) == Some(&b'"') {
            i += 1;
            while i < v.len() && v[i] != b'"' {
                if v[i] == b'\\' && i + 1 < v.len() {
                    i += 1;
                }
                val.push(v[i]);
                i += 1;
            }
            while i < v.len() && v[i] != b';' {
                i += 1;
            }
        } else {
            let st = i;
            while i < v.len() && v[i] != b';' {
                i += 1;
            }
            val = trim(&v[st..i]).to_vec();
        }
        if !name.is_empty() {
            params.push((name, val));
        }
    }
    Typed { main, params }
}

fn upper(v: &[u8]) -> Vec<u8> {
    v.to_ascii_uppercase()
}

fn params(out: &mut Vec<u8>, p: &[(Vec<u8>, Vec<u8>)]) {
    if p.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (n, (k, v)) in p.iter().enumerate() {
        if n > 0 {
            out.push(b' ');
        }
        wire::string(out, &upper(k));
        out.push(b' ');
        wire::string(out, v);
    }
    out.push(b')');
}

/// What a part's headers say about it.
struct PartHead {
    ctype: Vec<u8>,
    subtype: Vec<u8>,
    params: Vec<(Vec<u8>, Vec<u8>)>,
    id: Option<Vec<u8>>,
    description: Option<Vec<u8>>,
    encoding: Vec<u8>,
    md5: Option<Vec<u8>>,
    disposition: Option<Typed>,
    language: Option<Vec<u8>>,
    location: Option<Vec<u8>>,
}

fn part_head(block: &[u8], default_message: bool) -> PartHead {
    let ct = header_value(block, "Content-Type").map(|v| parse_typed(&v));
    let (ctype, subtype, params) = match ct {
        Some(t) if t.main.contains(&b'/') => {
            let slash = t.main.iter().position(|&b| b == b'/').unwrap_or(0);
            (upper(trim(&t.main[..slash])), upper(trim(&t.main[slash + 1..])), t.params)
        }
        _ if default_message => (b"MESSAGE".to_vec(), b"RFC822".to_vec(), Vec::new()),
        _ => (b"TEXT".to_vec(), b"PLAIN".to_vec(), vec![(b"CHARSET".to_vec(), b"US-ASCII".to_vec())]),
    };
    PartHead {
        ctype,
        subtype,
        params,
        id: header_value(block, "Content-ID"),
        description: header_value(block, "Content-Description"),
        encoding: header_value(block, "Content-Transfer-Encoding").map(|v| upper(&v)).filter(|v| !v.is_empty()).unwrap_or_else(|| b"7BIT".to_vec()),
        md5: header_value(block, "Content-MD5"),
        disposition: header_value(block, "Content-Disposition").map(|v| parse_typed(&v)).filter(|t| !t.main.is_empty()),
        language: header_value(block, "Content-Language"),
        location: header_value(block, "Content-Location"),
    }
}

/// The extension data shared by every non-multipart body: md5 disposition language location.
fn ext_tail(out: &mut Vec<u8>, h: &PartHead, md5: bool) {
    if md5 {
        out.push(b' ');
        wire::nstring(out, h.md5.as_deref());
    }
    out.push(b' ');
    match &h.disposition {
        None => out.extend_from_slice(b"NIL"),
        Some(d) => {
            out.push(b'(');
            wire::string(out, &upper(&d.main));
            out.push(b' ');
            params(out, &d.params);
            out.push(b')');
        }
    }
    out.push(b' ');
    match &h.language {
        None => out.extend_from_slice(b"NIL"),
        Some(l) => {
            out.push(b'(');
            for (n, tag) in l.split(|&b| b == b',').map(trim).filter(|t| !t.is_empty()).enumerate() {
                if n > 0 {
                    out.push(b' ');
                }
                wire::string(out, tag);
            }
            out.push(b')');
        }
    }
    out.push(b' ');
    wire::nstring(out, h.location.as_deref());
}

/// BODY (`extensible` false) or BODYSTRUCTURE of the message `m`. `text` overrides the root
/// body (the caller's own header split of the stored file).
pub(crate) fn body(out: &mut Vec<u8>, m: MessageRef<'_>, text: Option<&[u8]>, extensible: bool) {
    part(out, &m.root_part(), text, extensible, false);
}

fn part(out: &mut Vec<u8>, p: &MessagePart<'_>, body_override: Option<&[u8]>, ext: bool, in_digest: bool) {
    let h = part_head(p.raw_headers(), in_digest);
    if p.is_multipart() {
        out.push(b'(');
        let digest = h.subtype.eq_ignore_ascii_case(b"DIGEST");
        for c in p.children() {
            part(out, &c, None, ext, digest);
        }
        if p.children().len() == 0 {
            // RFC 3501 needs at least one body: an empty multipart reads as an empty text part.
            out.extend_from_slice(b"(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0)");
        }
        out.push(b' ');
        wire::string(out, &h.subtype);
        if ext {
            out.push(b' ');
            params(out, &h.params);
            ext_tail(out, &h, false);
        }
        out.push(b')');
        return;
    }
    let raw = body_override.unwrap_or_else(|| p.raw_body());
    out.push(b'(');
    wire::string(out, &h.ctype);
    out.push(b' ');
    wire::string(out, &h.subtype);
    out.push(b' ');
    params(out, &h.params);
    out.push(b' ');
    wire::nstring(out, h.id.as_deref());
    out.push(b' ');
    wire::nstring(out, h.description.as_deref());
    out.push(b' ');
    wire::string(out, &h.encoding);
    out.extend_from_slice(format!(" {}", raw.len()).as_bytes());
    let nested = p.nested().filter(|_| h.ctype == b"MESSAGE" && h.subtype == b"RFC822");
    if let Some(m) = nested {
        out.push(b' ');
        envelope(out, split(m.raw()).0);
        out.push(b' ');
        part(out, &m.root_part(), (!m.root_part().is_multipart()).then(|| split(m.raw()).1), ext, false);
        out.extend_from_slice(format!(" {}", lines(raw)).as_bytes());
    } else if h.ctype == b"TEXT" {
        out.extend_from_slice(format!(" {}", lines(raw)).as_bytes());
    }
    if ext {
        ext_tail(out, &h, true);
    }
    out.push(b')');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(head: &[u8]) -> String {
        let mut v = Vec::new();
        envelope(&mut v, head);
        String::from_utf8_lossy(&v).into_owned()
    }

    #[test]
    fn header_split() {
        assert_eq!(header_len(b"A: b\r\n\r\nx"), Some(8));
        assert_eq!(header_len(b"A: b\n\nx"), Some(6));
        assert_eq!(header_len(b"\r\nx"), Some(2));
        assert_eq!(header_len(b"A: b\r\n"), None);
        assert_eq!(split(b"A: b\r\n"), (&b"A: b\r\n"[..], &b""[..]));
    }

    #[test]
    fn field_iteration_and_filter() {
        let h = b"A: 1\r\nB: 2\r\n  more\r\nc: 3\r\n\r\nbody: x\r\n";
        let names: Vec<_> = fields(h).map(|f| f.name.to_vec()).collect();
        assert_eq!(names, vec![b"A".to_vec(), b"B".to_vec(), b"c".to_vec()]);
        assert_eq!(filter_fields(h, &[b"b", b"C"], false), b"B: 2\r\n  more\r\nc: 3\r\n\r\n");
        assert_eq!(filter_fields(h, &[b"b", b"C"], true), b"A: 1\r\n\r\n");
        assert_eq!(header_value(h, "b").unwrap(), b"2  more");
    }

    #[test]
    fn addresses() {
        assert_eq!(
            env(b"From: \"Doe, Jane\" <jane@x.org>, carl@x.org (Carl)\r\n"),
            "(NIL NIL ((\"Doe, Jane\" NIL \"jane\" \"x.org\")(NIL NIL \"carl\" \"x.org\")) \
             ((\"Doe, Jane\" NIL \"jane\" \"x.org\")(NIL NIL \"carl\" \"x.org\")) \
             ((\"Doe, Jane\" NIL \"jane\" \"x.org\")(NIL NIL \"carl\" \"x.org\")) NIL NIL NIL NIL NIL)"
        );
        assert_eq!(
            parse_addresses(b"undisclosed-recipients:;"),
            vec![Addr::GroupStart(b"undisclosed-recipients".to_vec()), Addr::GroupEnd]
        );
        assert_eq!(
            parse_addresses(b"<@route:a@b>"),
            vec![Addr::Mailbox { name: None, mailbox: b"a".to_vec(), host: Some(b"b".to_vec()) }]
        );
        assert_eq!(parse_addresses(b""), vec![]);
        assert_eq!(parse_addresses(b"<>"), vec![]);
    }
}
