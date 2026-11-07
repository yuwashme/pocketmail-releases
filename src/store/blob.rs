//! Blob files: names, the tmp write (O_EXCL, size check, fsync) and the rename into place with
//! directory fsyncs, so a committed row always has its whole file on disk.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::{StoreError, mkdirs};

/// "<received_ms>-<16 lowercase hex>.eml" (random suffix).
pub(crate) fn name(received_ms: i64) -> Result<String, StoreError> {
    let r = getrandom::u64().map_err(|e| StoreError::Io(io::Error::other(e.to_string())))?;
    Ok(format!("{received_ms}-{r:016x}.eml"))
}

/// Remove everything inside `dir` (startup clean-up of tmp/).
pub(crate) fn empty_dir(dir: &Path) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() { fs::remove_dir_all(&p)? } else { fs::remove_file(&p)? }
    }
    Ok(())
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// What goes in front of the body.
pub(crate) enum Prefix {
    /// Written unless the body itself starts with a `Return-Path:` field (case-insensitive).
    ReturnPath(Vec<u8>),
    /// Always written.
    Always(Vec<u8>),
}

const RETURN_PATH: &[u8] = b"return-path:";

/// Write prefix + body to a new file at `path` (0600, must not exist), check that the body was
/// exactly `expected` bytes, fsync. Returns the file length. On any error the file is removed.
pub(crate) fn write_tmp(path: &Path, prefix: Prefix, body: &mut dyn Read, expected: u64, capture: bool) -> Result<(u64,Vec<u8>), StoreError> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    let r = fill(file, prefix, body, expected, capture);
    if r.is_err() {
        let _ = fs::remove_file(path);
    }
    r
}

fn fill(file: File, prefix: Prefix, body: &mut dyn Read, expected: u64, capture: bool) -> Result<(u64,Vec<u8>), StoreError> {
    // Never read more than one byte past the promised size: enough to detect a mismatch.
    let mut body = body.take(expected.saturating_add(1));
    let mut head = [0u8; RETURN_PATH.len()];
    let mut n = 0;
    while n < head.len() {
        match body.read(&mut head[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let head = &head[..n];
    let prefix: &[u8] = match &prefix {
        Prefix::ReturnPath(p) if !(head.len() == RETURN_PATH.len() && head.eq_ignore_ascii_case(RETURN_PATH)) => p,
        Prefix::ReturnPath(_) => &[],
        Prefix::Always(p) => p,
    };
    let mut preview = Vec::new();
    let mut w = BufWriter::with_capacity((expected as usize).clamp(1024,64*1024), file);
    w.write_all(prefix)?;
    w.write_all(head)?;
    let preview_len = if capture {
        preview.extend_from_slice(head);
        let n = (&mut body).take((32768-head.len()) as u64).read_to_end(&mut preview)?;
        w.write_all(&preview[head.len()..])?;
        n
    } else { 0 };
    let rest = io::copy(&mut body, &mut w)?;
    let actual = (head.len()+preview_len) as u64 + rest;
    if actual != expected {
        return Err(StoreError::SizeMismatch { expected, actual });
    }
    let file = w.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    Ok((prefix.len() as u64 + actual,preview))
}

/// Rename `tmp` to `dest` (both on the data dir's file system), creating missing directories
/// below `root`, then fsync the directories whose entries changed.
pub(crate) fn install(tmp: &Path, dest: &Path, root: &Path) -> io::Result<()> {
    let parent = dest.parent().ok_or_else(|| io::Error::other("blob path has no parent"))?;
    let created = !parent.is_dir();
    if created {
        mkdirs(parent)?;
    }
    if dest.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} exists", dest.display())));
    }
    fs::rename(tmp, dest)?;
    fsync_dir(parent)?;
    if created {
        // New month (or account) directory: its entry lives in the ancestors up to root.
        let mut d = parent;
        while let Some(up) = d.parent() {
            fsync_dir(up)?;
            if up == root {
                break;
            }
            d = up;
        }
    }
    Ok(())
}
