use crate::error::WxPayError;

const DEFAULT_BASE_URL: &str = "https://api.mch.weixin.qq.com";

pub struct ClientConfig {
    pub(crate) mch_id: String,
    pub(crate) serial_no: String,
    pub(crate) api_v3_key: String,
    pub(crate) private_key_pem: String,
    pub(crate) http_client: Option<reqwest::Client>,
    pub(crate) base_url: String,
}

impl ClientConfig {
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder {
            mch_id: None,
            serial_no: None,
            api_v3_key: None,
            private_key_pem: None,
            http_client: None,
            base_url: None,
        }
    }

    /// Returns the merchant ID.
    pub fn mch_id(&self) -> &str {
        &self.mch_id
    }

    /// Returns the certificate serial number.
    pub fn serial_no(&self) -> &str {
        &self.serial_no
    }

    /// Returns the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

pub struct ClientConfigBuilder {
    mch_id: Option<String>,
    serial_no: Option<String>,
    api_v3_key: Option<String>,
    private_key_pem: Option<String>,
    http_client: Option<reqwest::Client>,
    base_url: Option<String>,
}

impl ClientConfigBuilder {
    pub fn mch_id(mut self, mch_id: impl Into<String>) -> Self {
        self.mch_id = Some(mch_id.into());
        self
    }

    pub fn serial_no(mut self, serial_no: impl Into<String>) -> Self {
        self.serial_no = Some(serial_no.into());
        self
    }

    pub fn api_v3_key(mut self, api_v3_key: impl Into<String>) -> Self {
        self.api_v3_key = Some(api_v3_key.into());
        self
    }

    pub fn private_key_pem(mut self, private_key_pem: impl Into<String>) -> Self {
        self.private_key_pem = Some(private_key_pem.into());
        self
    }

    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn build(self) -> Result<ClientConfig, WxPayError> {
        let mch_id = self
            .mch_id
            .ok_or_else(|| WxPayError::Config("mch_id is required".into()))?;
        let serial_no = self
            .serial_no
            .ok_or_else(|| WxPayError::Config("serial_no is required".into()))?;
        let api_v3_key = self
            .api_v3_key
            .ok_or_else(|| WxPayError::Config("api_v3_key is required".into()))?;
        let private_key_pem = self
            .private_key_pem
            .ok_or_else(|| WxPayError::Config("private_key_pem is required".into()))?;

        if api_v3_key.len() != 32 {
            return Err(WxPayError::Config(format!(
                "api_v3_key must be 32 bytes, got {}",
                api_v3_key.len()
            )));
        }

        Ok(ClientConfig {
            mch_id,
            serial_no,
            api_v3_key,
            private_key_pem,
            http_client: self.http_client,
            base_url: self
                .base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a valid RSA PKCS#1 PEM private key for testing.
    fn test_private_key_pem() -> String {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    /// A valid 32-byte API v3 key for testing.
    fn test_api_v3_key() -> &'static str {
        "01234567890123456789012345678901" // exactly 32 bytes
    }

    #[test]
    fn test_builder_success() {
        let pem = test_private_key_pem();
        let config = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .build();

        assert!(config.is_ok());
    }

    /// Extract error from a Result<ClientConfig, WxPayError>, panicking if Ok.
    fn expect_err(result: Result<ClientConfig, WxPayError>) -> WxPayError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn test_builder_missing_mch_id() {
        let pem = test_private_key_pem();
        let result = ClientConfig::builder()
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .build();

        let err = expect_err(result);
        assert!(matches!(err, WxPayError::Config(msg) if msg.contains("mch_id")));
    }

    #[test]
    fn test_builder_missing_serial_no() {
        let pem = test_private_key_pem();
        let result = ClientConfig::builder()
            .mch_id("1900000001")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .build();

        let err = expect_err(result);
        assert!(matches!(err, WxPayError::Config(msg) if msg.contains("serial_no")));
    }

    #[test]
    fn test_builder_missing_api_v3_key() {
        let pem = test_private_key_pem();
        let result = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .private_key_pem(pem)
            .build();

        let err = expect_err(result);
        assert!(matches!(err, WxPayError::Config(msg) if msg.contains("api_v3_key")));
    }

    #[test]
    fn test_builder_missing_private_key_pem() {
        let result = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .build();

        let err = expect_err(result);
        assert!(matches!(err, WxPayError::Config(msg) if msg.contains("private_key_pem")));
    }

    #[test]
    fn test_builder_invalid_api_v3_key_length() {
        let pem = test_private_key_pem();
        let result = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key("too_short")
            .private_key_pem(pem)
            .build();

        let err = expect_err(result);
        assert!(matches!(err, WxPayError::Config(msg) if msg.contains("32 bytes")));
    }

    #[test]
    fn test_builder_default_base_url() {
        let pem = test_private_key_pem();
        let config = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .build()
            .unwrap();

        assert_eq!(config.base_url(), "https://api.mch.weixin.qq.com");
    }

    #[test]
    fn test_builder_custom_base_url() {
        let pem = test_private_key_pem();
        let custom_url = "https://custom.example.com";
        let config = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .base_url(custom_url)
            .build()
            .unwrap();

        assert_eq!(config.base_url(), custom_url);
    }

    #[test]
    fn test_getters() {
        let pem = test_private_key_pem();
        let config = ClientConfig::builder()
            .mch_id("1900000001")
            .serial_no("SERIAL123")
            .api_v3_key(test_api_v3_key())
            .private_key_pem(pem)
            .build()
            .unwrap();

        assert_eq!(config.mch_id(), "1900000001");
        assert_eq!(config.serial_no(), "SERIAL123");
        assert_eq!(config.base_url(), "https://api.mch.weixin.qq.com");
    }
}
