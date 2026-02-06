use std::sync::Arc;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::RsaPrivateKey;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::cert::manager::PlatformCertManager;
use crate::config::ClientConfig;
use crate::crypto::sign::{build_authorization_header, build_sign_message, sign_sha256_rsa};
use crate::crypto::verify::verify_signature;
use crate::error::{ApiErrorResponse, WxPayError};

pub struct WxPayClient {
    pub(crate) config: ClientConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) signing_key: SigningKey<Sha256>,
    pub(crate) cert_manager: Arc<RwLock<PlatformCertManager>>,
}

impl WxPayClient {
    /// Returns the merchant ID.
    pub fn mch_id(&self) -> &str {
        &self.config.mch_id
    }

    /// Create a new WeChat Pay client.
    ///
    /// Parses the private key PEM and fetches platform certificates from `/v3/certificates`.
    pub async fn new(config: ClientConfig) -> Result<Self, WxPayError> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(&config.private_key_pem)
            .or_else(|_| {
                use rsa::pkcs8::DecodePrivateKey;
                RsaPrivateKey::from_pkcs8_pem(&config.private_key_pem)
            })
            .map_err(|e| WxPayError::InvalidKey(format!("parse private key: {e}")))?;

        let signing_key = SigningKey::<Sha256>::new(private_key.clone());

        let http = config
            .http_client
            .clone()
            .unwrap_or_default();

        let cert_manager = Arc::new(RwLock::new(PlatformCertManager::new()));

        let client = Self {
            config,
            http,
            signing_key,
            cert_manager,
        };

        client.ensure_certs().await?;

        Ok(client)
    }

    /// Ensure platform certificates are loaded and fresh.
    pub(crate) async fn ensure_certs(&self) -> Result<(), WxPayError> {
        let needs_refresh = {
            let mgr = self.cert_manager.read().await;
            mgr.is_empty() || mgr.needs_refresh()
        };

        if needs_refresh {
            let mut mgr = self.cert_manager.write().await;
            if mgr.is_empty() || mgr.needs_refresh() {
                debug!("refreshing platform certificates");
                mgr.refresh(
                    &self.http,
                    &self.config.base_url,
                    &self.config.mch_id,
                    &self.config.serial_no,
                    &self.signing_key,
                    &self.config.api_v3_key,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Send a signed POST request and return the deserialized response.
    pub(crate) async fn post<Req, Resp>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, WxPayError>
    where
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
    {
        let body_str = serde_json::to_string(body)?;
        let resp = self.do_request("POST", path, &body_str).await?;
        let resp_body = self.verify_and_read(resp).await?;
        serde_json::from_str(&resp_body).map_err(WxPayError::from)
    }

    /// Send a signed POST request that returns no body (HTTP 204).
    pub(crate) async fn post_no_content<Req>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<(), WxPayError>
    where
        Req: serde::Serialize,
    {
        let body_str = serde_json::to_string(body)?;
        let resp = self.do_request("POST", path, &body_str).await?;
        let status = resp.status();

        let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
        let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
        let wechat_signature = header_str(&resp, "Wechatpay-Signature");
        let wechat_serial = header_str(&resp, "Wechatpay-Serial");

        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return self.parse_api_error(&body);
        }

        if let (Some(ts), Some(nonce), Some(sig), Some(serial)) = (
            &wechat_timestamp,
            &wechat_nonce,
            &wechat_signature,
            &wechat_serial,
        ) {
            let mgr = self.cert_manager.read().await;
            if let Some(cert) = mgr.get_cert(serial) {
                let valid = verify_signature(&cert.verifying_key, ts, nonce, &body, sig)?;
                if !valid {
                    return Err(WxPayError::VerifyError(
                        "response signature verification failed".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Send a signed GET request and return the deserialized response.
    pub(crate) async fn get<Resp>(&self, path: &str) -> Result<Resp, WxPayError>
    where
        Resp: serde::de::DeserializeOwned,
    {
        let resp = self.do_request("GET", path, "").await?;
        let resp_body = self.verify_and_read(resp).await?;
        serde_json::from_str(&resp_body).map_err(WxPayError::from)
    }

    /// Send a signed GET request and return raw bytes (for bill downloads).
    pub(crate) async fn get_bytes(&self, url: &str) -> Result<bytes::Bytes, WxPayError> {
        let path = if url.starts_with("http") {
            extract_path(url, &self.config.base_url)
        } else {
            url.to_string()
        };
        let full_url = if url.starts_with("http") {
            url.to_string()
        } else {
            format!("{}{url}", self.config.base_url)
        };

        self.ensure_certs().await?;

        let timestamp = current_timestamp();
        let nonce = uuid::Uuid::new_v4().to_string();

        let sign_msg = build_sign_message("GET", &path, timestamp, &nonce, "");
        let signature = sign_sha256_rsa(&self.signing_key, &sign_msg)?;
        let auth = build_authorization_header(
            &self.config.mch_id,
            &self.config.serial_no,
            timestamp,
            &nonce,
            &signature,
        );

        let resp = self
            .http
            .get(&full_url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .header("User-Agent", "wxp-rust-sdk/0.1.0")
            .send()
            .await?;

        let status = resp.status();
        let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
        let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
        let wechat_signature = header_str(&resp, "Wechatpay-Signature");
        let wechat_serial = header_str(&resp, "Wechatpay-Serial");

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return self.parse_api_error(&body);
        }

        let data = resp.bytes().await.map_err(WxPayError::Http)?;

        if let (Some(ts), Some(nonce), Some(sig), Some(serial)) = (
            &wechat_timestamp,
            &wechat_nonce,
            &wechat_signature,
            &wechat_serial,
        ) {
            let body_str = String::from_utf8_lossy(&data);
            let mgr = self.cert_manager.read().await;
            if let Some(cert) = mgr.get_cert(serial) {
                let valid = verify_signature(&cert.verifying_key, ts, nonce, &body_str, sig)?;
                if !valid {
                    return Err(WxPayError::VerifyError(
                        "response signature verification failed".into(),
                    ));
                }
            }
        }

        Ok(data)
    }

    async fn do_request(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<reqwest::Response, WxPayError> {
        self.ensure_certs().await?;
        debug!(method, path, "sending signed request");

        let timestamp = current_timestamp();
        let nonce = uuid::Uuid::new_v4().to_string();
        let full_url = format!("{}{path}", self.config.base_url);

        let sign_msg = build_sign_message(method, path, timestamp, &nonce, body);
        let signature = sign_sha256_rsa(&self.signing_key, &sign_msg)?;
        let auth = build_authorization_header(
            &self.config.mch_id,
            &self.config.serial_no,
            timestamp,
            &nonce,
            &signature,
        );

        let http_method: reqwest::Method = method
            .parse()
            .map_err(|_| WxPayError::Config(format!("invalid HTTP method: {method}")))?;

        let mut req = self
            .http
            .request(http_method, &full_url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .header("User-Agent", "wxp-rust-sdk/0.1.0");

        if method != "GET" {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }

        req.send().await.map_err(WxPayError::Http)
    }

    async fn verify_and_read(&self, resp: reqwest::Response) -> Result<String, WxPayError> {
        let status = resp.status();

        let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
        let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
        let wechat_signature = header_str(&resp, "Wechatpay-Signature");
        let wechat_serial = header_str(&resp, "Wechatpay-Serial");

        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return self.parse_api_error(&body);
        }

        match (&wechat_timestamp, &wechat_nonce, &wechat_signature, &wechat_serial) {
            (Some(ts), Some(nonce), Some(sig), Some(serial)) => {
                let mgr = self.cert_manager.read().await;
                if let Some(cert) = mgr.get_cert(serial) {
                    let valid = verify_signature(&cert.verifying_key, ts, nonce, &body, sig)?;
                    if !valid {
                        return Err(WxPayError::VerifyError(
                            "response signature verification failed".into(),
                        ));
                    }
                } else if !mgr.is_empty() {
                    warn!(serial, "platform certificate not found for serial");
                    return Err(WxPayError::VerifyError(format!(
                        "platform certificate not found for serial: {serial}"
                    )));
                }
                // cert store empty = bootstrap, skip
            }
            _ => {
                let mgr = self.cert_manager.read().await;
                if !mgr.is_empty() {
                    warn!("response missing signature headers");
                    return Err(WxPayError::VerifyError(
                        "response missing signature headers".into(),
                    ));
                }
            }
        }

        Ok(body)
    }

    fn parse_api_error<T>(&self, body: &str) -> Result<T, WxPayError> {
        match serde_json::from_str::<ApiErrorResponse>(body) {
            Ok(err_resp) => Err(WxPayError::Api {
                code: err_resp.code,
                message: err_resp.message,
                detail: err_resp.detail.map(Box::new),
            }),
            Err(_) => Err(WxPayError::Api {
                code: "UNKNOWN".into(),
                message: body.to_string(),
                detail: None,
            }),
        }
    }
}

pub(crate) fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub(crate) fn current_timestamp_str() -> String {
    current_timestamp().to_string()
}

fn header_str(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn extract_path(url: &str, base_url: &str) -> String {
    if let Some(stripped) = url.strip_prefix(base_url) {
        stripped.to_string()
    } else if let Some((_scheme, rest)) = url.split_once("://") {
        rest.find('/').map_or("/".to_string(), |i| rest[i..].to_string())
    } else {
        url.to_string()
    }
}
