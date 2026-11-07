//! Synology Mail Server: a small mail server for a Synology NAS.
//!
//! Modules: `config` (env only), `log` (stderr), `time` (unix <-> IMAP dates) and `store`
//! (protocol-neutral, sync storage), `tls` (rustls builders), `inbound` (Worker puller), `listener`
//! (TLS accept loop and connection caps), `imap` (IMAP4rev1; STORE and SEARCH included) and `web`
//! (settings pages over HTTPS).

pub mod config;
pub mod imap;
pub mod inbound;
pub mod listener;
pub mod log;
pub mod store;
pub mod time;
pub mod tls;
pub mod web;

pub mod outgoing;
