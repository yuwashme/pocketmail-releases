//! Per-connection state machine (not authenticated / authenticated / selected / logout),
//! the command framer with its limits, autologout and the uid list of the selected mailbox.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use imap_codec::decode::Decoder;
use imap_codec::imap_types::auth::AuthMechanism;
use imap_codec::imap_types::command::CommandBody;
use imap_codec::imap_types::core::Tag;
use imap_codec::imap_types::mailbox::{ListMailbox, Mailbox};
use imap_codec::imap_types::status::StatusDataItemName;
use imap_codec::{AuthenticateDataCodec, CommandCodec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use super::{Clock, ServerConfig, wire};
use crate::store::{AccountId, Flags, MailboxId, Store, StoreError};

const CAPABILITY: &str = "IMAP4rev1 AUTH=PLAIN";
/// A whole command, literals included (several 64 KiB literals in one command are refused).
const MAX_MESSAGE: usize = 256 * 1024;
/// After an over-long line, read and drop at most this much looking for its end, so the close
/// that follows does not reset the connection before the client reads the BAD.
const MAX_DISCARD: usize = 1024 * 1024;
/// Read buffer kept between commands; anything larger is released.
const KEEP_RBUF: usize = 4 * 1024;

pub(crate) enum State {
    NotAuth,
    Auth(AccountId),
    Selected(Selected),
}

pub(crate) struct Selected {
    pub account: AccountId,
    pub mailbox: MailboxId,
    pub read_only: bool,
    /// Sequence number n is `uids[n - 1]`.
    pub uids: Vec<u32>,
    /// \Recent for this session: floor < uid <= upto for any (floor, upto).
    pub recent: Vec<(u32, u32)>,
    /// UIDNEXT when the uid list was last refreshed.
    pub uidnext: u32,
    pub modseq:u64,
}

impl Selected {
    pub fn is_recent(&self, uid: u32) -> bool {
        self.recent.iter().any(|&(floor, upto)| uid > floor && uid <= upto)
    }
    fn recent_count(&self) -> usize {
        self.uids.iter().filter(|&&u| self.is_recent(u)).count()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    No,
    Bad,
}

/// The tagged completion of a command; the text may start with a response code.
pub(crate) struct Reply {
    pub status: Status,
    pub text: Cow<'static, str>,
}

impl Reply {
    pub fn ok(t: impl Into<Cow<'static, str>>) -> Reply {
        Reply { status: Status::Ok, text: t.into() }
    }
    pub fn no(t: impl Into<Cow<'static, str>>) -> Reply {
        Reply { status: Status::No, text: t.into() }
    }
    pub fn bad(t: impl Into<Cow<'static, str>>) -> Reply {
        Reply { status: Status::Bad, text: t.into() }
    }
    pub fn internal() -> Reply {
        Reply::no("[UNAVAILABLE] Internal server error")
    }
}

enum Flow {
    Continue,
    Close,
}

enum Frame {
    Message(Vec<u8>),
    StagedAppend(Vec<u8>,tempfile::NamedTempFile,i64),
    /// Over-long line, over-size literal, LITERAL+ or an over-size command: BAD, then close.
    Refuse { tag: String, text: &'static str, discard_line: bool },
    /// APPEND announced a literal: answered NO at once instead of `+` (RFC 3501 7.5 lets the
    /// server refuse a synchronizing literal), so the client never sends the message.
    RefuseAppend { tag: String },
    Timeout,
    Eof,
}

#[allow(clippy::enum_variant_names)]
enum Line {
    /// `rbuf[..end]` is one line including its LF.
    Line(usize),
    TooLong,
    Eof,
}

pub(crate) struct Session {
    io: TlsStream<TcpStream>,
    rbuf: Vec<u8>,
    peer: SocketAddr,
    pub(crate) store: Arc<Store>,
    config: Arc<ServerConfig>,
    clock: Arc<dyn Clock>,
    pub(crate) state: State,
    bad_count: u32,
}

pub(crate) async fn run(io: TlsStream<TcpStream>, peer: SocketAddr, store: Arc<Store>, config: Arc<ServerConfig>, clock: Arc<dyn Clock>) {
    let mut s = Session { io, rbuf: Vec::new(), peer, store, config, clock, state: State::NotAuth, bad_count: 0 };
    if let Err(e) = s.serve().await {
        crate::log_debug!("imap: connection from {} ended: {e}", s.peer.ip());
    }
}

impl Session {
    async fn serve(&mut self) -> io::Result<()> {
        self.send(format!("* OK [CAPABILITY {CAPABILITY}] IMAP4rev1 server ready\r\n").as_bytes()).await?;
        self.io.flush().await?;
        loop {
            let frame = self.next_frame().await?;
            let flow = match frame {
                Frame::Eof => return Ok(()),
                Frame::Timeout => {
                    self.send(b"* BYE Autologout; idle for too long\r\n").await?;
                    Flow::Close
                }
                Frame::Refuse { tag, text, discard_line } => {
                    self.send(format!("{tag} BAD {text}\r\n").as_bytes()).await?;
                    self.io.flush().await?;
                    if discard_line {
                        self.discard_line().await?;
                    }
                    Flow::Close
                }
                Frame::RefuseAppend { tag } => {
                    let text = if matches!(self.state, State::NotAuth) { "Log in first" } else { "[TOOBIG] APPEND literal exceeds the configured limit" };
                    self.send(format!("{tag} NO {text}\r\n").as_bytes()).await?;
                    Flow::Continue
                }
                Frame::Message(msg) => self.handle(msg,None).await?,
                Frame::StagedAppend(msg,file,size) => self.handle(msg,Some((file,size))).await?,
            };
            self.io.flush().await?;
            if let Flow::Close = flow {
                let _ = self.io.shutdown().await;
                return Ok(());
            }
            if self.rbuf.is_empty() {
                self.rbuf = Vec::new();
            } else if self.rbuf.capacity() > KEEP_RBUF {
                self.rbuf.shrink_to(KEEP_RBUF);
            }
        }
    }

    // ---- output ----------------------------------------------------------------------------

    pub(crate) async fn send(&mut self, b: &[u8]) -> io::Result<()> {
        self.io.write_all(b).await
    }

    // ---- framing ---------------------------------------------------------------------------

    /// The next complete command, waiting at most `autologout` (one clock sleep per wait).
    async fn next_frame(&mut self) -> io::Result<Frame> {
        let clock = self.clock.clone();
        let autologout = self.config.autologout;
        tokio::select! {
            f = self.read_message() => f,
            _ = clock.sleep(autologout) => Ok(Frame::Timeout),
        }
    }

    async fn fill(&mut self) -> io::Result<bool> {
        self.rbuf.reserve(2048);
        Ok(self.io.read_buf(&mut self.rbuf).await? > 0)
    }

    async fn read_line(&mut self) -> io::Result<Line> {
        let max = self.config.max_line;
        let mut scanned = 0;
        loop {
            if let Some(p) = self.rbuf[scanned..].iter().position(|&b| b == b'\n') {
                let end = scanned + p + 1;
                let content = end - 1 - usize::from(end >= 2 && self.rbuf[end - 2] == b'\r');
                return Ok(if content > max { Line::TooLong } else { Line::Line(end) });
            }
            scanned = self.rbuf.len();
            if scanned > max + 1 {
                return Ok(Line::TooLong);
            }
            if !self.fill().await? {
                return Ok(Line::Eof);
            }
        }
    }

    async fn read_message(&mut self) -> io::Result<Frame> {
        let mut msg = Vec::new();
        loop {
            let end = match self.read_line().await? {
                Line::Eof => return Ok(Frame::Eof),
                Line::TooLong => {
                    let tag = if msg.is_empty() { tag_of(&self.rbuf) } else { tag_of(&msg) };
                    return Ok(Frame::Refuse { tag, text: "Command line too long", discard_line: true });
                }
                Line::Line(end) => end,
            };
            msg.extend_from_slice(&self.rbuf[..end]);
            self.rbuf.drain(..end);
            let n = match literal_announcement(&msg) {
                None => return Ok(Frame::Message(msg)),
                Some(Err(())) => {
                    return Ok(Frame::Refuse { tag: tag_of(&msg), text: "Non-synchronizing literals are not supported", discard_line: false });
                }
                Some(Ok(n)) => n,
            };
            if is_append(&msg) {
                if matches!(self.state, State::NotAuth) || n>25*1024*1024 {
                    return Ok(Frame::RefuseAppend {tag:tag_of(&msg)});
                }
                // Decode the metadata with an empty final literal. Earlier mailbox-name
                // literals still take the normal bounded command path below.
                let start=msg.iter().rposition(|&b|b==b'{').unwrap();
                let mut header=msg[..start].to_vec();
                header.extend_from_slice(b"{0}\r\n\r\n");
                if matches!(CommandCodec::default().decode(&header),Ok(([],c)) if matches!(c.body,CommandBody::Append{..})) {
                    let file=tempfile::NamedTempFile::new_in(self.store.data_dir().join("tmp"))?;
                    let mut output=tokio::fs::File::from_std(file.reopen()?);
                    self.send(b"+ Ready for literal data\r\n").await?;
                    self.io.flush().await?;
                    let mut remaining=n;
                    let mut nul=false;
                    while remaining>0 {
                        if self.rbuf.is_empty() && !self.fill().await? {return Ok(Frame::Eof);}
                        let take=remaining.min(self.rbuf.len());
                        nul |= self.rbuf[..take].contains(&0);
                        output.write_all(&self.rbuf[..take]).await?;
                        self.rbuf.drain(..take);
                        remaining-=take;
                    }
                    output.flush().await?;
                    let Line::Line(end)=self.read_line().await? else {return Ok(Frame::Eof)};
                    if nul || &self.rbuf[..end]!=b"\r\n" {return Ok(Frame::Refuse{tag:tag_of(&msg),text:"Invalid APPEND literal",discard_line:false});}
                    self.rbuf.drain(..end);
                    return Ok(Frame::StagedAppend(header,file,n as i64));
                }
            }
            if n > self.config.max_literal || msg.len().saturating_add(n) > MAX_MESSAGE {
                return Ok(Frame::Refuse { tag: tag_of(&msg), text: "Literal too large", discard_line: false });
            }
            self.send(b"+ Ready for literal data\r\n").await?;
            self.io.flush().await?;
            while self.rbuf.len() < n {
                if !self.fill().await? {
                    return Ok(Frame::Eof);
                }
            }
            msg.extend_from_slice(&self.rbuf[..n]);
            self.rbuf.drain(..n);
        }
    }

    /// Drop input up to the end of the current (over-long) line, at most MAX_DISCARD bytes.
    async fn discard_line(&mut self) -> io::Result<()> {
        let mut dropped = 0;
        loop {
            if let Some(p) = self.rbuf.iter().position(|&b| b == b'\n') {
                self.rbuf.drain(..=p);
                return Ok(());
            }
            dropped += self.rbuf.len();
            self.rbuf.clear();
            if dropped > MAX_DISCARD || !self.fill().await? {
                return Ok(());
            }
        }
    }

    /// One continuation line (AUTHENTICATE), under the same autologout. None: close.
    async fn read_continuation(&mut self) -> io::Result<Option<Vec<u8>>> {
        let clock = self.clock.clone();
        let autologout = self.config.autologout;
        let line = tokio::select! {
            l = self.read_line() => l?,
            _ = clock.sleep(autologout) => {
                self.send(b"* BYE Autologout; idle for too long\r\n").await?;
                return Ok(None);
            }
        };
        match line {
            Line::Line(end) => Ok(Some(self.rbuf.drain(..end).collect())),
            Line::TooLong => {
                self.send(b"* BYE Line too long\r\n").await?;
                Ok(None)
            }
            Line::Eof => Ok(None),
        }
    }

    // ---- dispatch --------------------------------------------------------------------------

    async fn handle(&mut self, msg: Vec<u8>,staged:Option<(tempfile::NamedTempFile,i64)>) -> io::Result<Flow> {
        let cmd = match CommandCodec::default().decode(&msg) {
            Ok(([], cmd)) => cmd,
            _ => return self.syntax_error(&tag_of(&msg), "Syntax error or unknown command").await,
        };
        let tag = cmd.tag.as_ref().to_string();
        let authed = !matches!(self.state, State::NotAuth);
        let selected = matches!(self.state, State::Selected(_));
        let allow_expunge = !matches!(cmd.body,CommandBody::Fetch{..}|CommandBody::Store{..}|CommandBody::Search{..});
        let reply = match cmd.body {
            CommandBody::Capability => {
                self.send(format!("* CAPABILITY {CAPABILITY}\r\n").as_bytes()).await?;
                Reply::ok("CAPABILITY completed")
            }
            CommandBody::Noop => Reply::ok("NOOP completed"),
            CommandBody::Logout => {
                self.send(b"* BYE Logging out\r\n").await?;
                self.send(format!("{tag} OK LOGOUT completed\r\n").as_bytes()).await?;
                return Ok(Flow::Close);
            }

            CommandBody::Login { .. } | CommandBody::Authenticate { .. } if authed => Reply::no("Already authenticated"),
            CommandBody::Login { username, password } => {
                let login = String::from_utf8_lossy(username.as_ref()).into_owned();
                let pw = String::from_utf8_lossy(password.declassify().as_ref()).into_owned();
                self.login(login, pw, true).await
            }
            CommandBody::Authenticate { mechanism, initial_response } => {
                if !matches!(mechanism, AuthMechanism::Plain) {
                    Reply::no("Unsupported authentication mechanism")
                } else if initial_response.is_some() {
                    Reply::bad("SASL-IR is not supported")
                } else {
                    match self.authenticate_plain().await? {
                        Some(r) => r,
                        None => return Ok(Flow::Close),
                    }
                }
            }

            // Anything below needs a login; not a syntax error, so NO (does not count as a BAD).
            CommandBody::Select { .. }
            | CommandBody::Examine { .. }
            | CommandBody::Create { .. }
            | CommandBody::Delete { .. }
            | CommandBody::Rename { .. }
            | CommandBody::Subscribe { .. }
            | CommandBody::Unsubscribe { .. }
            | CommandBody::List { .. }
            | CommandBody::Lsub { .. }
            | CommandBody::Status { .. }
            | CommandBody::Append { .. }
            | CommandBody::Check
            | CommandBody::Close
            | CommandBody::Expunge
            | CommandBody::Search { .. }
            | CommandBody::Fetch { .. }
            | CommandBody::Store { .. }
            | CommandBody::Copy { .. }
                if !authed =>
            {
                Reply::no("Log in first")
            }

            CommandBody::Select { mailbox } => self.select(&mailbox, false).await?,
            CommandBody::Examine { mailbox } => self.select(&mailbox, true).await?,
            CommandBody::Create { .. } | CommandBody::Delete { .. } | CommandBody::Rename { .. } => {
                Reply::no("[CANNOT] Only INBOX exists; mailboxes cannot be created, deleted or renamed")
            }
            CommandBody::Append { mailbox, flags,date,message } => {
                let account=self.account().unwrap();
                let name=mailbox_name(&mailbox);
                let mask=super::fetch::flag_mask(&flags);
                let raw=message.as_ref().to_vec();
                let date=date.map(|d|d.as_ref().timestamp()).unwrap_or_else(crate::store::now_unix);
                write_reply(self.blocking(move|s| {
                    let dest=s.find_mailbox(account,&name)?.ok_or_else(||StoreError::NotFound(name))?;
                    if let Some((file,size))=staged {s.append_staged(dest.id,mask,date,file,size)} else {s.append_message(dest.id,mask,date,&raw)}
                }).await,"APPEND completed")
            },
            CommandBody::Subscribe { mailbox } => self.subscribe(&mailbox, true).await,
            CommandBody::Unsubscribe { mailbox } => self.subscribe(&mailbox, false).await,
            CommandBody::List { reference, mailbox_wildcard } => self.list(&reference, &mailbox_wildcard, false).await?,
            CommandBody::Lsub { reference, mailbox_wildcard } => self.list(&reference, &mailbox_wildcard, true).await?,
            CommandBody::Status { mailbox, item_names } => self.status(&mailbox, &item_names).await?,

            CommandBody::Check | CommandBody::Close | CommandBody::Expunge | CommandBody::Search { .. } | CommandBody::Fetch { .. } | CommandBody::Store { .. } | CommandBody::Copy { .. }
                if !selected =>
            {
                Reply::no("No mailbox selected")
            }
            CommandBody::Check => Reply::ok("CHECK completed"),
            CommandBody::Close => {
                let State::Selected(sel)=&self.state else {unreachable!()};
                let (account,mb,ro)=(sel.account,sel.mailbox,sel.read_only);
                let result=if ro {Ok(())} else {self.blocking(move|s|s.expunge_messages(mb)).await};
                if result.is_ok(){self.state=State::Auth(account);}
                write_reply(result,"CLOSE completed")
            }
            CommandBody::Expunge => {
                let State::Selected(sel)=&self.state else {unreachable!()};
                let mb=sel.mailbox;
                if sel.read_only {Reply::no("[READ-ONLY] Mailbox is read-only")} else {
                    write_reply(self.blocking(move|s|s.expunge_messages(mb)).await,"EXPUNGE completed")
                }
            }
            CommandBody::Copy { mailbox,sequence_set,uid } => {
                let State::Selected(sel)=&self.state else {unreachable!()};
                let (account,mb)=(sel.account,sel.mailbox);
                if let Some(targets)=super::fetch::resolve(&sequence_set,&sel.uids,uid){
                    let name=mailbox_name(&mailbox);
                    write_reply(self.blocking(move|s|{
                        let dest=s.find_mailbox(account,&name)?.ok_or_else(||StoreError::NotFound(name))?;
                        s.copy_messages(mb,dest.id,&targets.into_iter().map(|(_,u)|u).collect::<Vec<_>>())
                    }).await,"COPY completed")
                } else {Reply::bad("Invalid message sequence number")}
            }
            CommandBody::Fetch { sequence_set, macro_or_item_names, uid } => {
                super::fetch::fetch(self, &sequence_set, macro_or_item_names, uid).await?
            }
            CommandBody::Store { sequence_set, kind, response, flags, uid } => {
                super::fetch::store(self, &sequence_set, kind, response, &flags, uid).await?
            }
            CommandBody::Search { charset, criteria, uid } => super::search::search(self, charset.as_ref(), &criteria, uid).await?,

            // IDLE, UNSELECT, ENABLE, MOVE, COMPRESS, QUOTA...: not offered (IMAP4rev1 only).
            _ => return self.syntax_error(&tag, "Command not supported").await,
        };
        if matches!(self.state, State::Selected(_)) {
            self.report_new_mail(allow_expunge).await?;
        }
        let status = match reply.status {
            Status::Ok => "OK",
            Status::No => "NO",
            Status::Bad => "BAD",
        };
        self.send(format!("{tag} {status} {}\r\n", reply.text).as_bytes()).await?;
        if reply.status == Status::Bad && !authed {
            return self.count_bad().await;
        }
        Ok(Flow::Continue)
    }

    async fn syntax_error(&mut self, tag: &str, text: &str) -> io::Result<Flow> {
        self.send(format!("{tag} BAD {text}\r\n").as_bytes()).await?;
        if matches!(self.state, State::NotAuth) { self.count_bad().await } else { Ok(Flow::Continue) }
    }

    async fn count_bad(&mut self) -> io::Result<Flow> {
        self.bad_count += 1;
        if self.bad_count >= self.config.max_bad_before_login {
            crate::log_info!("imap: closing connection from {}: too many invalid commands before login", self.peer.ip());
            self.send(b"* BYE Too many invalid commands\r\n").await?;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// Run a store call off the async thread.
    pub(crate) async fn blocking<T: Send + 'static>(&self, f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static) -> Result<T, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&store)).await.unwrap_or_else(|e| Err(StoreError::Io(io::Error::other(e.to_string()))))
    }

    fn account(&self) -> Option<AccountId> {
        match &self.state {
            State::NotAuth => None,
            State::Auth(a) => Some(*a),
            State::Selected(s) => Some(s.account),
        }
    }

    // ---- authentication --------------------------------------------------------------------

    /// Verify `login` / `password` (the store runs a dummy verify for unknown logins). `allowed`
    /// false: fail after the verify (foreign authzid), so timing does not tell the cases apart.
    async fn login(&mut self, login: String, password: String, allowed: bool) -> Reply {
        let who = login.clone();
        let r = self.blocking(move |s| s.authenticate(&login, &password)).await;
        match r {
            Ok(Some(id)) if allowed => {
                crate::log_info!("imap: {who} logged in from {}", self.peer.ip());
                self.state = State::Auth(id);
                Reply::ok("Logged in")
            }
            Ok(_) => {
                crate::log_info!("imap: failed login for {who:?} from {}", self.peer.ip());
                let clock = self.clock.clone();
                clock.sleep(self.config.auth_failure_delay).await;
                Reply::no("[AUTHENTICATIONFAILED] Authentication failed")
            }
            Err(e) => {
                crate::log_error!("imap: authenticate failed: {e:?}");
                Reply::internal()
            }
        }
    }

    /// AUTHENTICATE PLAIN after the command line: `+`, one base64 line, verify. None: close.
    async fn authenticate_plain(&mut self) -> io::Result<Option<Reply>> {
        self.send(b"+ \r\n").await?;
        self.io.flush().await?;
        let Some(line) = self.read_continuation().await? else { return Ok(None) };
        if line.strip_suffix(b"\n").map(|l| l.strip_suffix(b"\r").unwrap_or(l)) == Some(b"*") {
            return Ok(Some(Reply::bad("AUTHENTICATE cancelled")));
        }
        let data = match AuthenticateDataCodec::default().decode(&line) {
            Ok(([], d)) => d.0.declassify().clone(),
            _ => return Ok(Some(Reply::bad("Invalid base64 response"))),
        };
        let mut parts = data.split(|&b| b == 0);
        let (Some(authzid), Some(authcid), Some(pw), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Ok(Some(Reply::bad("Invalid PLAIN response")));
        };
        let allowed = authzid.is_empty() || authzid == authcid;
        let login = String::from_utf8_lossy(authcid).into_owned();
        let pw = String::from_utf8_lossy(pw).into_owned();
        Ok(Some(self.login(login, pw, allowed).await))
    }

    // ---- mailboxes -------------------------------------------------------------------------

    async fn select(&mut self, mailbox: &Mailbox<'_>, read_only: bool) -> io::Result<Reply> {
        let Some(account) = self.account() else { return Ok(Reply::no("Log in first")) };
        // A failed SELECT leaves the selected state too (RFC 3501 6.3.1).
        self.state = State::Auth(account);
        let name = mailbox_name(mailbox);
        let r = self
            .blocking(move |s| {
                let Some(mb) = s.find_mailbox(account, &name)? else { return Ok(None) };
                let claim = if read_only { None } else { Some(s.claim_recent(mb.id)?) };
                let info = s.mailbox(mb.id)?;
                let msgs = s.messages(mb.id)?;
                Ok(Some((info, msgs, claim)))
            })
            .await;
        let (info, msgs, claim) = match r {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(Reply::no("No such mailbox")),
            Err(e) => {
                crate::log_error!("imap: SELECT failed: {e:?}");
                return Ok(Reply::internal());
            }
        };
        let recent = match claim {
            Some(c) => vec![(c.floor, c.upto)],
            None => vec![(info.recent_uid, u32::MAX)],
        };
        let sel = Selected {
            account,
            mailbox: info.id,
            read_only,
            uids: msgs.iter().map(|m| m.uid).collect(),
            recent,
            uidnext: info.uidnext,
            modseq:info.highest_modseq,
        };
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"* FLAGS (\\Answered \\Flagged \\Seen \\Draft \\Deleted)\r\n");
        out.extend_from_slice(format!("* {} EXISTS\r\n* {} RECENT\r\n", sel.uids.len(), sel.recent_count()).as_bytes());
        if let Some(i) = msgs.iter().position(|m| !m.flags.contains(Flags::SEEN)) {
            out.extend_from_slice(format!("* OK [UNSEEN {}] First unseen\r\n", i + 1).as_bytes());
        }
        out.extend_from_slice(format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", info.uidvalidity).as_bytes());
        out.extend_from_slice(format!("* OK [UIDNEXT {}] Predicted next UID\r\n", info.uidnext).as_bytes());
        if read_only {
            out.extend_from_slice(b"* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n");
        } else {
            out.extend_from_slice(b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Seen \\Draft \\Deleted)] Limited\r\n");
        }
        self.send(&out).await?;
        self.state = State::Selected(sel);
        Ok(if read_only { Reply::ok("[READ-ONLY] EXAMINE completed") } else { Reply::ok("[READ-WRITE] SELECT completed") })
    }

    async fn subscribe(&mut self, mailbox: &Mailbox<'_>, on: bool) -> Reply {
        let Some(account) = self.account() else { return Reply::no("Log in first") };
        let name = mailbox_name(mailbox);
        let r = self
            .blocking(move |s| match s.find_mailbox(account, &name)? {
                Some(mb) => s.set_subscribed(mb.id, on).map(|_| true),
                None => Ok(false),
            })
            .await;
        match r {
            Ok(true) if on => Reply::ok("SUBSCRIBE completed"),
            Ok(true) => Reply::ok("UNSUBSCRIBE completed"),
            Ok(false) => Reply::no("No such mailbox"),
            Err(e) => {
                crate::log_error!("imap: SUBSCRIBE failed: {e:?}");
                Reply::internal()
            }
        }
    }

    async fn list(&mut self, reference: &Mailbox<'_>, pattern: &ListMailbox<'_>, lsub: bool) -> io::Result<Reply> {
        let Some(account) = self.account() else { return Ok(Reply::no("Log in first")) };
        let what = if lsub { "LSUB" } else { "LIST" };
        let pattern: &[u8] = match pattern {
            ListMailbox::Token(t) => t.as_ref(),
            ListMailbox::String(s) => s.as_ref(),
        };
        if pattern.is_empty() {
            if !lsub {
                self.send(b"* LIST (\\Noselect) \"/\" \"\"\r\n").await?;
            }
            return Ok(Reply::ok(format!("{what} completed")));
        }
        let mut full = match reference {
            Mailbox::Inbox => b"INBOX".to_vec(),
            Mailbox::Other(o) => o.as_ref().to_vec(),
        };
        full.extend_from_slice(pattern);
        let mailboxes = match self.blocking(move |s| s.mailboxes(account)).await {
            Ok(m) => m,
            Err(e) => {
                crate::log_error!("imap: {what} failed: {e:?}");
                return Ok(Reply::internal());
            }
        };
        let mut out = Vec::new();
        for mb in mailboxes.iter().filter(|m| !lsub || m.subscribed) {
            let hit = if mb.name == "INBOX" {
                glob(&full.to_ascii_uppercase(), b"INBOX")
            } else {
                glob(&full, mb.name.as_bytes())
            };
            if hit {
                out.extend_from_slice(format!("* {what} () \"/\" ").as_bytes());
                wire::astring(&mut out, mb.name.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
        self.send(&out).await?;
        Ok(Reply::ok(format!("{what} completed")))
    }

    async fn status(&mut self, mailbox: &Mailbox<'_>, items: &[StatusDataItemName]) -> io::Result<Reply> {
        let Some(account) = self.account() else { return Ok(Reply::no("Log in first")) };
        if items.iter().any(|i| {
            !matches!(
                i,
                StatusDataItemName::Messages
                    | StatusDataItemName::Recent
                    | StatusDataItemName::UidNext
                    | StatusDataItemName::UidValidity
                    | StatusDataItemName::Unseen
            )
        }) {
            return Ok(Reply::bad("Unsupported STATUS item"));
        }
        let name = mailbox_name(mailbox);
        let r = self
            .blocking(move |s| {
                let Some(mb) = s.find_mailbox(account, &name)? else { return Ok(None) };
                let msgs = s.messages(mb.id)?;
                Ok(Some((mb, msgs)))
            })
            .await;
        let (mb, msgs) = match r {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(Reply::no("No such mailbox")),
            Err(e) => {
                crate::log_error!("imap: STATUS failed: {e:?}");
                return Ok(Reply::internal());
            }
        };
        let mut vals = Vec::new();
        for i in items {
            vals.push(match i {
                StatusDataItemName::Messages => format!("MESSAGES {}", msgs.len()),
                StatusDataItemName::Recent => format!("RECENT {}", msgs.iter().filter(|m| m.uid > mb.recent_uid).count()),
                StatusDataItemName::UidNext => format!("UIDNEXT {}", mb.uidnext),
                StatusDataItemName::UidValidity => format!("UIDVALIDITY {}", mb.uidvalidity),
                _ => format!("UNSEEN {}", msgs.iter().filter(|m| !m.flags.contains(Flags::SEEN)).count()),
            });
        }
        let mut out = b"* STATUS ".to_vec();
        wire::astring(&mut out, mb.name.as_bytes());
        out.extend_from_slice(format!(" ({})\r\n", vals.join(" ")).as_bytes());
        self.send(&out).await?;
        Ok(Reply::ok("STATUS completed"))
    }

    /// New deliveries since the uid list was built: `* n EXISTS` and `* r RECENT`, once each.
    pub(crate) async fn report_new_mail(&mut self,allow_expunge:bool) -> io::Result<()> {
        let State::Selected(sel) = &self.state else { return Ok(()) };
        let (id, read_only, known,modseq) = (sel.mailbox, sel.read_only, sel.uidnext,sel.modseq);
        let r = self
            .blocking(move |s| {
                let info = s.mailbox(id)?;
                if info.uidnext == known && info.highest_modseq==modseq {
                    return Ok(None);
                }
                let claim = if read_only { None } else { Some(s.claim_recent(id)?) };
                let msgs = s.messages(id)?;
                Ok(Some((info.uidnext,info.highest_modseq, msgs.into_iter().map(|m| m.uid).collect::<Vec<u32>>(), claim)))
            })
            .await;
        let (uidnext,new_modseq, uids, claim) = match r {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(()),
            Err(e) => {
                crate::log_error!("imap: new-mail check failed: {e:?}");
                return Ok(());
            }
        };
        let State::Selected(sel) = &mut self.state else { return Ok(()) };
        let mut line=String::new();
        if let Some(c)=claim && c.upto>c.floor {sel.recent.push((c.floor,c.upto));}
        if !allow_expunge && sel.uids.iter().any(|u|uids.binary_search(u).is_err()){return Ok(());}
        let mut seq=0;
        sel.uids.retain(|u|{
            if uids.binary_search(u).is_ok(){seq+=1;true}else{line.push_str(&format!("* {} EXPUNGE\r\n",seq+1));false}
        });
        let changed=sel.uids.len()!=uids.len();
        sel.uidnext=uidnext;sel.modseq=new_modseq;sel.uids=uids;
        if changed {line.push_str(&format!("* {} EXISTS\r\n* {} RECENT\r\n",sel.uids.len(),sel.recent_count()));}
        self.send(line.as_bytes()).await
    }
}

/// The store's name for a decoded mailbox (INBOX canonical; others as sent, lossy UTF-8).
fn mailbox_name(m: &Mailbox<'_>) -> String {
    match m {
        Mailbox::Inbox => "INBOX".to_string(),
        Mailbox::Other(o) => String::from_utf8_lossy(o.as_ref()).into_owned(),
    }
}

/// Tag of a raw command for a BAD response: the bytes before the first space if they make a valid
/// tag, else `*`.
fn tag_of(msg: &[u8]) -> String {
    let end = msg.iter().position(|&b| b == b' ' || b == b'\r' || b == b'\n').unwrap_or(msg.len());
    match Tag::try_from(&msg[..end]) {
        Ok(t) => t.as_ref().to_string(),
        Err(_) => "*".to_string(),
    }
}

/// The command word of a raw command is APPEND (`tag SP "APPEND" SP ...`, any case).
fn is_append(msg: &[u8]) -> bool {
    let mut words = msg.splitn(3, |&b| b == b' ');
    let (Some(_tag), Some(cmd)) = (words.next(), words.next()) else { return false };
    cmd.eq_ignore_ascii_case(b"APPEND")
}

/// `{n}` (Ok(n)) or `{n+}` (Err) at the end of the last line of `msg`, before CRLF.
fn literal_announcement(msg: &[u8]) -> Option<Result<usize, ()>> {
    let l = msg.strip_suffix(b"\n")?;
    let l = l.strip_suffix(b"\r").unwrap_or(l);
    let l = l.strip_suffix(b"}")?;
    let open = l.iter().rposition(|&b| b == b'{')?;
    let digits = &l[open + 1..];
    let (digits, plus) = match digits.strip_suffix(b"+") {
        Some(d) => (d, true),
        None => (digits, false),
    };
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if plus {
        return Some(Err(()));
    }
    // Ten digits fit in u64; anything over usize::MAX is "too large" anyway.
    let n: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(Ok(usize::try_from(n).unwrap_or(usize::MAX)))
}

/// LIST pattern match: `*` matches anything, `%` anything but the delimiter `/`.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|i| glob(rest, &name[i..])),
        Some((b'%', rest)) => {
            let stop = name.iter().position(|&b| b == b'/').unwrap_or(name.len());
            (0..=stop).any(|i| glob(rest, &name[i..]))
        }
        Some((&c, rest)) => name.first() == Some(&c) && glob(rest, &name[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_globs() {
        for p in ["*", "%", "INBOX", "IN*", "I%", "*X", "%%"] {
            assert!(glob(p.as_bytes(), b"INBOX"), "{p}");
        }
        for p in ["Sent", "INBOX/*", "X*", "%/%", "INBOX/", "INBOXX"] {
            assert!(!glob(p.as_bytes(), b"INBOX"), "{p}");
        }
        assert!(glob(b"INBOX/%", b"INBOX/a"));
        assert!(!glob(b"INBOX/%", b"INBOX/a/b"));
        assert!(glob(b"INBOX/*", b"INBOX/a/b"));
    }

    #[test]
    fn literal_announcements() {
        assert_eq!(literal_announcement(b"A LOGIN {5}\r\n"), Some(Ok(5)));
        assert_eq!(literal_announcement(b"A LOGIN {5+}\r\n"), Some(Err(())));
        assert_eq!(literal_announcement(b"A LOGIN \"{5}\"\r\n"), None);
        assert_eq!(literal_announcement(b"A LOGIN {}\r\n"), None);
        assert_eq!(literal_announcement(b"A X {9999999999}\r\n"), Some(Ok(9_999_999_999)));
        assert_eq!(literal_announcement(b"A X {99999999999}\r\n"), None);
    }

    #[test]
    fn append_detection() {
        assert!(is_append(b"A1 APPEND INBOX {5}\r\n"));
        assert!(is_append(b"A1 append {4}\r\n"));
        assert!(!is_append(b"A1 SEARCH SUBJECT {5}\r\n"));
        assert!(!is_append(b"APPEND\r\n"));
    }

    #[test]
    fn tags() {
        assert_eq!(tag_of(b"A1 FOO\r\n"), "A1");
        assert_eq!(tag_of(b"A+1 FOO\r\n"), "*");
        assert_eq!(tag_of(b"\r\n"), "*");
    }
}

fn write_reply(result:Result<(),StoreError>,success:&'static str)->Reply {
    match result {Ok(())=>Reply::ok(success),Err(StoreError::NotFound(_))=>Reply::no("[TRYCREATE] No such mailbox"),
        Err(StoreError::QuotaExceeded)=>Reply::no("[OVERQUOTA] Mailbox storage limit reached"),Err(e)=>{crate::log_error!("imap write: {e}");Reply::internal()}}
}
