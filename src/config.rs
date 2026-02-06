use crate::error::WxPayError;

const DEFAULT_BASE_URL: &str = "https://api.mch.weixin.qq.com";

pub struct ClientConfig {
    pub mch_id: String,
    pub serial_no: String,
    pub api_v3_key: String,
    pub private_key_pem: String,
    pub http_client: Option<reqwest::Client>,
    pub base_url: String,
}

pub struct ClientConfigBuilder {
    mch_id: Option<String>,
    serial_no: Option<String>,
    api_v3_key: Option<String>,
    private_key_pem: Option<String>,
    http_client: Option<reqwest::Client>,
    base_url: Option<String>,
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
            base_url: self.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        })
    }
}
