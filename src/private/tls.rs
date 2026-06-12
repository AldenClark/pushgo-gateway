use std::sync::Arc;

use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio_rustls::TlsAcceptor;

pub(crate) struct ServerTlsIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl ServerTlsIdentity {
    pub(crate) fn load(cert_path: &str, key_path: &str) -> Result<Self, String> {
        Ok(Self {
            certs: Self::load_certs(cert_path)?,
            key: Self::load_key(key_path)?,
        })
    }

    pub(crate) fn into_acceptor(
        self,
        alpn: &str,
        error_context: &str,
    ) -> Result<TlsAcceptor, String> {
        let mut tls = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs, self.key)
            .map_err(|err| format!("invalid {error_context} tls cert/key: {err}"))?;
        tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        Ok(TlsAcceptor::from(Arc::new(tls)))
    }

    fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|err| format!("{path}: {err}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read certs failed: {err}"))?;
        if certs.is_empty() {
            return Err("empty certificate chain".to_string());
        }
        Ok(certs)
    }

    fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
        PrivateKeyDer::from_pem_file(path).map_err(|err| format!("read private key failed: {err}"))
    }
}
