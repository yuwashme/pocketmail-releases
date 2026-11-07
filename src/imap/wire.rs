//! Hand-written response syntax (RFC 3501 section 9): atoms, quoted strings, literals, NIL.
//! imap-codec decodes commands only; every response byte is produced here or in the callers.

/// ATOM-CHAR: any CHAR except atom-specials (and `]`, a resp-special).
pub(crate) fn is_atom_char(b: u8) -> bool {
    b > 0x20 && b < 0x7f && !b"(){%*\"\\]".contains(&b)
}

/// An astring: a bare atom when that is unambiguous, otherwise a string.
pub(crate) fn astring(out: &mut Vec<u8>, s: &[u8]) {
    if !s.is_empty() && s.iter().all(|&b| is_atom_char(b)) && !s.eq_ignore_ascii_case(b"NIL") {
        out.extend_from_slice(s);
    } else {
        string(out, s);
    }
}

/// A quoted string when it is short 7-bit text without CR, LF or NUL, otherwise a literal.
pub(crate) fn string(out: &mut Vec<u8>, s: &[u8]) {
    if s.len() <= 1024 && s.iter().all(|&b| b != 0 && b != b'\r' && b != b'\n' && b < 0x80) {
        out.push(b'"');
        for &b in s {
            if b == b'"' || b == b'\\' {
                out.push(b'\\');
            }
            out.push(b);
        }
        out.push(b'"');
    } else {
        literal(out, s);
    }
}

pub(crate) fn nstring(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => string(out, s),
        None => out.extend_from_slice(b"NIL"),
    }
}

/// `{n}` CRLF and the bytes, NUL replaced by 0x80 (a literal may not carry NUL; one byte for one
/// byte keeps every size and offset; docs/DEVIATIONS.md).
pub(crate) fn literal(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", s.len()).as_bytes());
    let start = out.len();
    out.extend_from_slice(s);
    replace_nul(&mut out[start..]);
}

pub(crate) fn replace_nul(b: &mut [u8]) {
    for x in b.iter_mut().filter(|x| **x == 0) {
        *x = 0x80;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(f: impl Fn(&mut Vec<u8>)) -> String {
        let mut v = Vec::new();
        f(&mut v);
        String::from_utf8_lossy(&v).into_owned()
    }

    #[test]
    fn strings() {
        assert_eq!(s(|o| astring(o, b"INBOX")), "INBOX");
        assert_eq!(s(|o| astring(o, b"")), "\"\"");
        assert_eq!(s(|o| astring(o, b"nil")), "\"nil\"");
        assert_eq!(s(|o| astring(o, b"Sent Items")), "\"Sent Items\"");
        assert_eq!(s(|o| string(o, b"a\"b\\c")), "\"a\\\"b\\\\c\"");
        assert_eq!(s(|o| string(o, b"a\r\nb")), "{4}\r\na\r\nb");
        assert_eq!(s(|o| nstring(o, None)), "NIL");
        let mut v = Vec::new();
        string(&mut v, b"a\0b");
        assert_eq!(v, b"{3}\r\na\x80b");
    }
}
