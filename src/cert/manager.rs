use std::time::Duration;

use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use tracing::{debug, info};
use x509_cert::der::DecodePem;

use crate::cert::store::{InMemoryCertStore, PlatformCert};
use crate::crypto::decrypt::decrypt_aes_256_gcm;
use crate::crypto::sign::{build_authorization_header, build_sign_message, sign_sha256_rsa};
use crate::error::WxPayError;
use crate::model::cert::CertificatesResponse;

const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 3600); // 12 hours
const CERTIFICATES_PATH: &str = "/v3/certificates";

pub struct PlatformCertManager {
    store: InMemoryCertStore,
    refresh_interval: Duration,
}

impl PlatformCertManager {
    pub fn new() -> Self {
        Self {
            store: InMemoryCertStore::new(),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
        }
    }

    pub fn get_cert(&self, serial_no: &str) -> Option<&PlatformCert> {
        self.store.get(serial_no)
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn needs_refresh(&self) -> bool {
        self.store.needs_refresh(self.refresh_interval)
    }

    pub async fn refresh(
        &mut self,
        http: &reqwest::Client,
        base_url: &str,
        mch_id: &str,
        serial_no: &str,
        signing_key: &SigningKey<Sha256>,
        api_v3_key: &str,
    ) -> Result<(), WxPayError> {
        debug!("fetching platform certificates");
        let url = format!("{base_url}{CERTIFICATES_PATH}");
        let timestamp = crate::client::current_timestamp();
        let nonce = uuid::Uuid::new_v4().to_string();

        let sign_msg = build_sign_message("GET", CERTIFICATES_PATH, timestamp, &nonce, "");
        let signature = sign_sha256_rsa(signing_key, &sign_msg)?;
        let auth = build_authorization_header(mch_id, serial_no, timestamp, &nonce, &signature);

        let resp = http
            .get(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .header("User-Agent", "wxp-rust-sdk/0.1.0")
            .send()
            .await
            .map_err(WxPayError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(WxPayError::CertError(format!(
                "fetch certificates failed: status={status}, body={body}"
            )));
        }

        let cert_resp: CertificatesResponse = resp
            .json()
            .await
            .map_err(|e| WxPayError::CertError(format!("deserialize certificates: {e}")))?;

        let mut certs = Vec::new();
        for data in &cert_resp.data {
            let enc = &data.encrypt_certificate;
            let pem_str = decrypt_aes_256_gcm(
                api_v3_key,
                &enc.nonce,
                &enc.associated_data,
                &enc.ciphertext,
            )?;

            let public_key = extract_public_key_from_pem(&pem_str)?;
            let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

            certs.push(PlatformCert {
                serial_no: data.serial_no.clone(),
                effective_time: data.effective_time.clone(),
                expire_time: data.expire_time.clone(),
                public_key,
                verifying_key,
                certificate_pem: pem_str,
            });
        }

        info!(count = certs.len(), "platform certificates updated");
        self.store.update(certs);
        Ok(())
    }
}

impl Default for PlatformCertManager {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_public_key_from_pem(pem_str: &str) -> Result<rsa::RsaPublicKey, WxPayError> {
    use rsa::pkcs1::DecodeRsaPublicKey;

    let cert = x509_cert::Certificate::from_pem(pem_str)
        .map_err(|e| WxPayError::CertError(format!("parse X.509 certificate: {e}")))?;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    rsa::RsaPublicKey::from_pkcs1_der(spki_der)
        .map_err(|e| WxPayError::CertError(format!("parse RSA public key: {e}")))
}
