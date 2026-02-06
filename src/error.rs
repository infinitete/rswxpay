use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WxPayError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("WeChat Pay API error: code={code}, message={message}")]
    Api {
        code: String,
        message: String,
        detail: Option<Box<ApiErrorDetail>>,
    },

    #[error("Signature generation failed: {0}")]
    SignError(String),

    #[error("Signature verification failed: {0}")]
    VerifyError(String),

    #[error("Decryption failed: {0}")]
    DecryptError(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Certificate error: {0}")]
    CertError(String),

    #[error("Serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Notification error: {0}")]
    NotifyError(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiErrorDetail {
    pub field: Option<String>,
    pub value: Option<String>,
    pub issue: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub detail: Option<ApiErrorDetail>,
}
