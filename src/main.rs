//! `synology-mail-server` command line. Configuration comes from SSM_* environment variables (src/config.rs). Passwords are read from stdin, never from argv,
//! so they do not show up in `ps` or shell history.

use std::io::{self, BufRead, Read, IsTerminal, Write};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use synology_mail_server::config::Config;
use synology_mail_server::imap::{ImapServer, ServerConfig};
use synology_mail_server::inbound::http::HttpClient;
use synology_mail_server::inbound::worker_api::{WorkerApi, read_token_file};
use synology_mail_server::inbound::{Poller, TokioClock};
use synology_mail_server::log::{self, Level};
use synology_mail_server::store::Store;
use synology_mail_server::web::{WebConfig, WebServer};
use synology_mail_server::{log_error, log_info, log_warn, time, tls};

/// `handoff` rows (Worker keys already delivered) are kept this long.
const HANDOFF_KEEP: Duration = Duration::from_secs(40 * 24 * 3600);
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 3600);
/// After SIGINT/SIGTERM, running store calls get this long to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

const USAGE: &str = "usage:
  synology-mail-server serve
  synology-mail-server deliver <queue-id> <sender> <recipient>  (message from stdin)
  synology-mail-server account add <login>       (password from stdin)
  synology-mail-server account passwd <login>    (password from stdin)
  synology-mail-server account list
  synology-mail-server account admin <login> on|off
  synology-mail-server address add <address> <login>   (\"user@domain\" or catch-all \"@domain\")
  synology-mail-server address rm <address>
environment: SSM_DATA_DIR (required), SSM_LOG (error|warn|info|debug, default info);
  serve: SSM_TLS_CERT + SSM_TLS_KEY (PEM; IMAP is off without them), SSM_IMAP_LISTEN (default
  0.0.0.0:9993), SSM_IMAP_MAX_CONN, SSM_PULL_URL + SSM_PULL_TOKEN_FILE, SSM_PULL_INTERVAL_SECS,
  SSM_WEB_LISTEN (settings pages, default 0.0.0.0:8443, or off), SSM_WEB_ALLOW_PUBLIC (yes|no,
  default no: home network only), SSM_WEBMAIL_LISTEN (loopback HTTPS tunnel origin, default off),
  SSM_SENDMAIL (absolute path to a local Postfix sendmail program, enables Compose)";

enum Cmd<'a> {
    Serve,
    Deliver(&'a str, &'a str, &'a str),
    AccountAdd(&'a str),
    AccountPasswd(&'a str),
    AccountList,
    AccountAdmin(&'a str, bool),
    AddressAdd(&'a str, &'a str),
    AddressRm(&'a str),
}

fn parse(args: &[String]) -> Option<Cmd<'_>> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    Some(match a.as_slice() {
        ["deliver", key, sender, recipient] => Cmd::Deliver(key, sender, recipient),
        ["serve"] => Cmd::Serve,
        ["account", "add", login] => Cmd::AccountAdd(login),
        ["account", "passwd", login] => Cmd::AccountPasswd(login),
        ["account", "list"] => Cmd::AccountList,
        ["account", "admin", login, "on"] => Cmd::AccountAdmin(login, true),
        ["account", "admin", login, "off"] => Cmd::AccountAdmin(login, false),
        ["address", "add", address, login] => Cmd::AddressAdd(address, login),
        ["address", "rm", address] => Cmd::AddressRm(address),
        _ => return None,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("-h" | "--help" | "help")) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(cmd) = parse(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(1);
        }
    };
    log::set_level(Level::parse(&config.log).unwrap_or(Level::Info));
    let delivering = matches!(cmd, Cmd::Deliver(..));
    match run(cmd, &config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(if delivering { 75 } else { 1 })
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run(cmd: Cmd<'_>, config: &Config) -> Result<()> {
    if let Cmd::Serve = cmd {
        return serve(config);
    }
    let store = Store::open_admin(&config.data_dir)?;
    match cmd {
        Cmd::Serve => unreachable!(),
        Cmd::Deliver(id, from, to) => {
            if id.is_empty() || id.len() > 100 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err("invalid queue ID".into());
            }
            if store.route(to)?.is_none() { return Err("recipient has no mailbox".into()); }
            let mut raw = Vec::new();
            io::stdin().lock().take(25 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
            if raw.len() > 25 * 1024 * 1024 { return Err("message exceeds 25 MiB".into()); }
            let key = format!("smtp:{id}:{to}");
            let delivery = synology_mail_server::store::Delivery {
                key: &key, envelope_from: from, envelope_to: to, expected_size: raw.len() as u64,
                received_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64,
            };
            store.deliver(&delivery, &mut raw.as_slice())?;
        }
        Cmd::AccountAdd(login) => {
            let pw = read_password()?;
            store.create_account(login, &pw)?;
            println!("account {login} created");
        }
        Cmd::AccountPasswd(login) => {
            let pw = read_password()?;
            store.set_password(login, &pw)?;
            println!("password of {login} changed");
        }
        Cmd::AccountList => {
            let addresses = store.addresses()?;
            for a in store.accounts()? {
                let mine: Vec<&str> = addresses.iter().filter(|(_, l)| *l == a.login).map(|(addr, _)| addr.as_str()).collect();
                println!(
                    "{}\tcreated {}{}{}\t{}",
                    a.login,
                    time::format_rfc3339(a.created_at),
                    if a.admin { "\tADMIN" } else { "" },
                    if a.disabled { "\tDISABLED" } else { "" },
                    mine.join(" ")
                );
            }
        }
        Cmd::AccountAdmin(login, on) => {
            store.set_admin(login, on)?;
            println!("{login} is {} an admin", if on { "now" } else { "no longer" });
        }
        Cmd::AddressAdd(address, login) => {
            store.add_address(address, login)?;
            println!("{} -> {login}", address.to_lowercase());
        }
        Cmd::AddressRm(address) => {
            store.remove_address(address)?;
            println!("{} removed", address.to_lowercase());
        }
    }
    Ok(())
}

/// Run the puller and the IMAP and web listeners on one current-thread runtime until SIGINT/SIGTERM.
/// Everything that can be checked up front (TLS files, token file, listen address) is checked
/// before the store is opened, so a bad configuration exits with a message instead of half-starting.
/// The web listener is the exception: if it cannot start, a warning is logged and the rest runs.
fn serve(config: &Config) -> Result<()> {
    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(
            tls::server_config_from_files(cert, key)
                .map_err(|e| format!("cannot load SSM_TLS_CERT {} / SSM_TLS_KEY {}: {e}", cert.display(), key.display()))?,
        ),
        _ => None,
    };
    let tunnel_addr = std::env::var("SSM_WEBMAIL_LISTEN").ok()
        .filter(|v| !v.is_empty() && v != "off")
        .map(|v| v.parse::<std::net::SocketAddr>()).transpose()?;
    if let Some(addr) = tunnel_addr {
        if !addr.ip().is_loopback() || tls.is_none() {
            return Err("SSM_WEBMAIL_LISTEN needs a loopback address and TLS certificate".into());
        }
    }
    let api = match (&config.pull_url, &config.pull_token_file) {
        (Some(url), Some(file)) => {
            let token = read_token_file(file).map_err(|e| format!("cannot read SSM_PULL_TOKEN_FILE {}: {e}", file.display()))?;
            Some(WorkerApi::new(HttpClient::new(tls::client_config()), url, &token).map_err(|e| format!("SSM_PULL_URL: {e}"))?)
        }
        _ => None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .thread_keep_alive(Duration::from_secs(10))
        .build()?;
    let store = Arc::new(Store::open(&config.data_dir)?);
    log_info!("store open at {} ({} accounts)", config.data_dir.display(), store.accounts()?.len());

    let result = runtime.block_on(async {
        match tls {
            Some(tls) => {
                let listener = tokio::net::TcpListener::bind(config.imap_listen)
                    .await
                    .map_err(|e| format!("cannot listen on SSM_IMAP_LISTEN {}: {e}", config.imap_listen))?;
                let server_config = ServerConfig { max_conn: config.imap_max_conn, ..ServerConfig::new(tls.clone()) };
                let server = ImapServer::start(listener, store.clone(), server_config, Arc::new(TokioClock))?;
                log_info!("imap: listening on {} (implicit TLS)", server.local_addr());

                if let Some(addr) = tunnel_addr {
                    let listener = tokio::net::TcpListener::bind(addr).await?;
                    let cfg = WebConfig { allow_public: true, mailbox_only: true, ..WebConfig::new(tls.clone()) };
                    WebServer::start(listener, store.clone(), cfg, Arc::new(TokioClock))?;
                    log_info!("webmail: tunnel origin listening on {addr}");
                }
                match config.web_listen {
                    Some(addr) => {
                        let web_config = WebConfig { allow_public: config.web_allow_public, ..WebConfig::new(tls) };
                        let started = match tokio::net::TcpListener::bind(addr).await {
                            Ok(listener) => WebServer::start(listener, store.clone(), web_config, Arc::new(TokioClock)),
                            Err(e) => Err(e),
                        };
                        match started {
                            Ok(server) => {
                                let who = if config.web_allow_public { "any network" } else { "home network only" };
                                log_info!("web: listening on {} (settings pages, HTTPS, {who})", server.local_addr());
                                if let Some(path) = server.setup_path() {
                                    let at = server.local_addr();
                                    let host = if at.ip().is_unspecified() { format!("<this server's address>:{}", at.port()) } else { at.to_string() };
                                    log_info!("web: no admin yet: open https://{host}{path} within 1 hour to set up the first admin");
                                }
                            }
                            Err(e) => log_warn!("web: off: cannot listen on SSM_WEB_LISTEN {addr}: {e}"),
                        }
                    }
                    None => log_info!("web: off (SSM_WEB_LISTEN=off)"),
                }
            }
            None => {
                log_warn!("imap: off (SSM_TLS_CERT and SSM_TLS_KEY are not set)");
                log_warn!("web: off (SSM_TLS_CERT and SSM_TLS_KEY are not set)");
            }
        }
        // The poller's future is not Send, so it runs here on the runtime's own thread rather
        // than through tokio::spawn.
        let poller = async {
            match api {
                Some(api) => {
                    log_info!("inbound: pulling every {} s", config.pull_interval.as_secs());
                    Poller::new(api, store.clone(), config.pull_interval).run().await
                }
                None => {
                    log_warn!("inbound: off (SSM_PULL_URL is not set)");
                    std::future::pending().await
                }
            }
        };
        if let Some(path) = std::env::var_os("SSM_SENDMAIL").map(std::path::PathBuf::from).filter(|p|p.is_absolute()) {
            store.recover_outbox()?;
            tokio::spawn(synology_mail_server::outgoing::run(store.clone(),path));
        }
        tokio::spawn(prune_daily(store.clone()));
        log_rss();
        let signal = tokio::select! {
            () = poller => return Err("inbound poller stopped".into()),
            s = shutdown_signal() => s?,
        };
        log_info!("{signal}: shutting down");
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    // Tasks are dropped here; a store call already running in a blocking thread may finish.
    runtime.shutdown_timeout(SHUTDOWN_GRACE);
    drop(store);
    result
}

/// `Store::prune_handoff` at startup and then once a day.
async fn prune_daily(store: Arc<Store>) {
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let cutoff = now - HANDOFF_KEEP.as_secs() as i64;
        let s = store.clone();
        match tokio::task::spawn_blocking(move || s.prune_handoff(cutoff)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => log_info!("store: pruned {n} handoff rows older than 40 days"),
            Ok(Err(e)) => log_warn!("store: handoff prune failed: {e}"),
            Err(e) => log_warn!("store: handoff prune task failed: {e}"),
        }
        tokio::time::sleep(PRUNE_EVERY).await;
    }
}

async fn shutdown_signal() -> io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    })
}

/// Linux only (the NAS): resident memory after startup.
fn log_rss() {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return;
    };
    let kb = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next());
    if let Some(kb) = kb {
        log_info!("VmRSS {kb} kB");
    }
}

/// One line from stdin without its line ending. On a terminal: echo off (via `stty`), asked twice.
fn read_password() -> Result<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Ok(read_line(&mut stdin.lock())?);
    }
    let first = prompt("Password: ")?;
    if prompt("Again: ")? != first {
        return Err("passwords do not match".into());
    }
    Ok(first)
}

fn prompt(text: &str) -> Result<String> {
    eprint!("{text}");
    io::stderr().flush()?;
    let echo_off = stty("-echo");
    let line = read_line(&mut io::stdin().lock());
    if echo_off {
        stty("echo");
        eprintln!();
    } else {
        log_error!("could not turn terminal echo off; the password was visible");
    }
    Ok(line?)
}

fn stty(arg: &str) -> bool {
    Command::new("stty").arg(arg).stdin(Stdio::inherit()).status().map(|s| s.success()).unwrap_or(false)
}

fn read_line(r: &mut dyn BufRead) -> io::Result<String> {
    let mut s = String::new();
    r.read_line(&mut s)?;
    let trimmed = s.strip_suffix('\n').unwrap_or(&s);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    Ok(trimmed.to_string())
}
