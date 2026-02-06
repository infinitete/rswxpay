use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::cert::manager::{PlatformCertManager, fetch_platform_certs};
use crate::config::ClientConfig;
use crate::crypto::sign::{build_authorization_header, build_sign_message, sign_sha256_rsa};
use crate::crypto::verify::verify_signature;
use crate::error::{ApiErrorResponse, WxPayError};

/// Signature-related headers extracted from a WeChat Pay response.
struct ResponseSignatureHeaders {
    timestamp: Option<String>,
    nonce: Option<String>,
    signature: Option<String>,
    serial: Option<String>,
}

impl ResponseSignatureHeaders {
    fn from_response(resp: &reqwest::Response) -> Self {
        Self {
            timestamp: header_str(resp, "Wechatpay-Timestamp"),
            nonce: header_str(resp, "Wechatpay-Nonce"),
            signature: header_str(resp, "Wechatpay-Signature"),
            serial: header_str(resp, "Wechatpay-Serial"),
        }
    }

    fn has_all(&self) -> bool {
        self.timestamp.is_some()
            && self.nonce.is_some()
            && self.signature.is_some()
            && self.serial.is_some()
    }
}

pub struct WxPayClient {
    pub(crate) config: ClientConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) signing_key: Arc<SigningKey<Sha256>>,
    pub(crate) cert_manager: Arc<RwLock<PlatformCertManager>>,
    /// Next cert refresh time as Unix epoch seconds.
    /// 0 means "needs refresh now" (initial state).
    next_cert_refresh: AtomicU64,
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

        let signing_key = Arc::new(SigningKey::<Sha256>::new(private_key.clone()));

        let http = config.http_client.clone().unwrap_or_default();

        let cert_manager = Arc::new(RwLock::new(PlatformCertManager::new()));

        let client = Self {
            config,
            http,
            signing_key,
            cert_manager,
            next_cert_refresh: AtomicU64::new(0),
        };

        client.ensure_certs().await?;

        Ok(client)
    }

    /// Ensure platform certificates are loaded and fresh.
    ///
    /// Uses an atomic timestamp on the fast path (no lock) to skip the check
    /// when certificates are known to be fresh. Only acquires the write lock
    /// briefly to swap in the new certificates.
    pub(crate) async fn ensure_certs(&self) -> Result<(), WxPayError> {
        let now = current_timestamp() as u64;
        if now < self.next_cert_refresh.load(Ordering::Acquire) {
            return Ok(());
        }

        // Slow path: fetch certs outside any lock to minimize lock hold time.
        let new_certs = fetch_platform_certs(
            &self.http,
            &self.config.base_url,
            &self.config.mch_id,
            &self.config.serial_no,
            &self.signing_key,
            &self.config.api_v3_key,
        )
        .await?;

        // Brief write lock only for the cert store swap.
        let mut mgr = self.cert_manager.write().await;
        mgr.update_certs(new_certs);
        drop(mgr);

        // Schedule next refresh in 12 hours.
        let refresh_at = current_timestamp() as u64 + 12 * 3600;
        self.next_cert_refresh.store(refresh_at, Ordering::Release);

        Ok(())
    }

    /// Send a signed POST request and return the deserialized response.
    pub(crate) async fn post<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp, WxPayError>
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
        let sig_headers = ResponseSignatureHeaders::from_response(&resp);
        let body = resp.text().await?;

        if !status.is_success() {
            return self.parse_api_error(&body);
        }

        self.verify_response_signature(&sig_headers, &body).await?;

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
        let signing_key = Arc::clone(&self.signing_key);
        let signature =
            tokio::task::spawn_blocking(move || sign_sha256_rsa(&signing_key, &sign_msg))
                .await
                .map_err(|e| WxPayError::SignError(format!("task join: {e}")))??;
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
        let sig_headers = ResponseSignatureHeaders::from_response(&resp);

        if !status.is_success() {
            let body = resp.text().await?;
            return self.parse_api_error(&body);
        }

        let data = resp.bytes().await.map_err(WxPayError::Http)?;

        // Only attempt UTF-8 conversion and signature verification when
        // signature headers are present. Binary responses (e.g. GZIP bills)
        // typically do not include signature headers.
        if sig_headers.has_all() {
            let body_str = String::from_utf8(data.to_vec()).map_err(|e| {
                WxPayError::VerifyError(format!("response body is not valid UTF-8: {e}"))
            })?;
            self.verify_response_signature(&sig_headers, &body_str)
                .await?;
        } else {
            self.verify_response_signature(&sig_headers, "").await?;
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
        // Move RSA signing to the blocking thread pool to avoid blocking
        // the async runtime (~1-3ms for RSA-2048 PKCS1v15 signing).
        let signing_key = Arc::clone(&self.signing_key);
        let signature =
            tokio::task::spawn_blocking(move || sign_sha256_rsa(&signing_key, &sign_msg))
                .await
                .map_err(|e| WxPayError::SignError(format!("task join: {e}")))??;
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
        let sig_headers = ResponseSignatureHeaders::from_response(&resp);
        let body = resp.text().await?;

        if !status.is_success() {
            return self.parse_api_error(&body);
        }

        self.verify_response_signature(&sig_headers, &body).await?;

        Ok(body)
    }

    /// Unified response signature verification.
    ///
    /// Logic:
    /// - If all four signature headers are present and cert store is non-empty,
    ///   the signature MUST verify successfully.
    /// - If all four signature headers are present but cert store is empty
    ///   (bootstrap phase), verification is skipped.
    /// - If any signature header is missing and cert store is non-empty,
    ///   returns an error (response should have been signed).
    /// - If any signature header is missing and cert store is empty
    ///   (bootstrap phase), verification is skipped.
    ///
    /// **Security note on bootstrap skip**: During the initial `/v3/certificates`
    /// fetch the cert store is empty, so RSA signature verification cannot be
    /// performed. This is safe because the fetched certificate ciphertext is
    /// encrypted with AES-256-GCM using `api_v3_key` as the key. An attacker
    /// without `api_v3_key` cannot produce validly-encrypted certificate data,
    /// so AES-GCM decryption provides implicit authentication of the bootstrap
    /// response. The security of this bootstrap depends entirely on `api_v3_key`
    /// remaining secret.
    async fn verify_response_signature(
        &self,
        headers: &ResponseSignatureHeaders,
        body: &str,
    ) -> Result<(), WxPayError> {
        match (
            &headers.timestamp,
            &headers.nonce,
            &headers.signature,
            &headers.serial,
        ) {
            (Some(ts), Some(nonce), Some(sig), Some(serial)) => {
                let mgr = self.cert_manager.read().await;
                if let Some(cert) = mgr.get_cert(serial) {
                    let valid = verify_signature(&cert.verifying_key, ts, nonce, body, sig)?;
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
                // cert store empty = bootstrap, skip verification (see safety note above)
            }
            _ => {
                let mgr = self.cert_manager.read().await;
                if !mgr.is_empty() {
                    warn!("response missing signature headers");
                    return Err(WxPayError::VerifyError(
                        "response missing signature headers".into(),
                    ));
                }
                // cert store empty = bootstrap, skip verification (see safety note above)
            }
        }

        Ok(())
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

/// Percent-encode a string so it is safe to use in a URL path segment or query value.
pub(crate) fn encode_path_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
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
        rest.find('/')
            .map_or("/".to_string(), |i| rest[i..].to_string())
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_path tests ---

    #[test]
    fn test_extract_path_with_matching_base_url() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi";
        let path = extract_path(url, base);
        assert_eq!(path, "/v3/pay/transactions/jsapi");
    }

    #[test]
    fn test_extract_path_with_different_host() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "https://other.example.com/v3/billdownload?token=abc";
        let path = extract_path(url, base);
        assert_eq!(path, "/v3/billdownload?token=abc");
    }

    #[test]
    fn test_extract_path_already_path() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "/v3/certificates";
        let path = extract_path(url, base);
        assert_eq!(path, "/v3/certificates");
    }

    #[test]
    fn test_extract_path_url_without_path() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "https://example.com";
        let path = extract_path(url, base);
        assert_eq!(path, "/");
    }

    // --- encode_path_segment tests ---

    #[test]
    fn test_encode_path_segment_plain() {
        let encoded = encode_path_segment("hello");
        assert_eq!(encoded, "hello");
    }

    #[test]
    fn test_encode_path_segment_special_chars() {
        let encoded = encode_path_segment("a/b&c=d");
        // NON_ALPHANUMERIC encodes everything except ASCII alphanumerics
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%2F")); // '/' encoded
        assert!(encoded.contains("%26")); // '&' encoded
        assert!(encoded.contains("%3D")); // '=' encoded
    }

    #[test]
    fn test_encode_path_segment_empty() {
        assert_eq!(encode_path_segment(""), "");
    }

    #[test]
    fn test_encode_path_segment_unicode() {
        let encoded = encode_path_segment("中文");
        assert!(!encoded.contains('中'));
        assert!(!encoded.contains('文'));
        // Each Chinese char is 3 UTF-8 bytes → 3 percent-encoded triplets
        assert_eq!(encoded.matches('%').count(), 6);
    }

    #[test]
    fn test_encode_path_segment_spaces() {
        let encoded = encode_path_segment("hello world");
        assert!(!encoded.contains(' '));
        assert!(encoded.contains("%20"));
    }

    // --- current_timestamp tests ---

    #[test]
    fn test_current_timestamp_is_positive() {
        let ts = current_timestamp();
        assert!(ts > 0);
        // Should be after 2024-01-01 (1704067200)
        assert!(ts > 1_704_067_200);
    }

    #[test]
    fn test_current_timestamp_str_is_numeric() {
        let ts_str = current_timestamp_str();
        assert!(ts_str.parse::<i64>().is_ok());
    }

    // --- more extract_path edge cases ---

    #[test]
    fn test_extract_path_with_query_string() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "https://api.mch.weixin.qq.com/v3/bill/tradebill?bill_date=2023-01-01";
        let path = extract_path(url, base);
        assert_eq!(path, "/v3/bill/tradebill?bill_date=2023-01-01");
    }

    #[test]
    fn test_extract_path_bare_string() {
        let base = "https://api.mch.weixin.qq.com";
        let url = "no-scheme-no-slash";
        let path = extract_path(url, base);
        assert_eq!(path, "no-scheme-no-slash");
    }
}
