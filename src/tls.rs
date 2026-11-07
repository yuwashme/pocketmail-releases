//! rustls configuration builders. Crypto provider: ring only (never aws-lc-rs). TLS 1.2 stays on (Outlook/Win10).

use std::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

#[derive(Debug)]
pub enum TlsError {
    /// Reading a PEM file failed (missing, unreadable).
    Io(io::Error),
    /// The certificate PEM holds no CERTIFICATE block.
    NoCertificate,
    /// The key PEM holds no private key block (PKCS#8, PKCS#1 or SEC1).
    NoPrivateKey,
    /// Malformed PEM.
    Pem(String),
    /// rustls refused the configuration (e.g. the key does not match the certificate).
    Rustls(rustls::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Io(e) => write!(f, "reading PEM file: {e}"),
            TlsError::NoCertificate => f.write_str("no CERTIFICATE block in the certificate PEM"),
            TlsError::NoPrivateKey => f.write_str("no private key block in the key PEM"),
            TlsError::Pem(e) => write!(f, "malformed PEM: {e}"),
            TlsError::Rustls(e) => write!(f, "TLS configuration refused: {e}"),
        }
    }
}

impl std::error::Error for TlsError {}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_with(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Client config for the Worker pull: Mozilla roots from webpki-roots, TLS 1.2 and 1.3, ring.
pub fn client_config() -> Arc<ClientConfig> {
    client_with(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
}

/// Client config that trusts only `roots` (tests inject a test CA here). TLS 1.2 and 1.3, ring.
pub fn client_config_with_roots(roots: Vec<CertificateDer<'static>>) -> Result<Arc<ClientConfig>, TlsError> {
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(r).map_err(TlsError::Rustls)?;
    }
    Ok(client_with(store))
}

fn pem_err(e: pem::Error) -> TlsError {
    TlsError::Pem(e.to_string())
}

/// Listener config from PEM bytes: certificate chain (leaf first) and one private key.
/// No client auth, TLS 1.2 and 1.3, ring.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let chain = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>().map_err(pem_err)?;
    if chain.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    let key = match PrivateKeyDer::from_pem_slice(key_pem) {
        Ok(k) => k,
        Err(pem::Error::NoItemsFound) => return Err(TlsError::NoPrivateKey),
        Err(e) => return Err(pem_err(e)),
    };
    // with_single_cert refuses a key whose public half differs from the leaf's.
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(TlsError::Rustls)?;
    Ok(Arc::new(config))
}

/// `server_config` from the files named by SSM_TLS_CERT and SSM_TLS_KEY.
pub fn server_config_from_files(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_pem = std::fs::read(cert).map_err(TlsError::Io)?;
    let key_pem = std::fs::read(key).map_err(TlsError::Io)?;
    server_config(&cert_pem, &key_pem)
}
