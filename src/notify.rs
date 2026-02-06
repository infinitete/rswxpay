use tracing::debug;

use crate::client::WxPayClient;
use crate::crypto::decrypt::decrypt_aes_256_gcm;
use crate::crypto::verify::verify_signature;
use crate::error::WxPayError;
use crate::model::notify::*;

impl WxPayClient {
    /// Parse and verify a WeChat Pay notification.
    ///
    /// 1. Verifies the signature from HTTP headers against the platform certificate
    /// 2. Deserializes the `NotifyEnvelope`
    ///
    /// Use `decrypt_notify_resource` to decrypt the resource ciphertext afterwards.
    pub async fn parse_notify(
        &self,
        headers: &NotifyHeaders,
        body: &str,
    ) -> Result<NotifyEnvelope, WxPayError> {
        self.ensure_certs().await?;

        // Verify timestamp freshness (±5 minutes)
        let ts: i64 = headers.timestamp.parse().map_err(|_| {
            WxPayError::NotifyError(format!(
                "invalid timestamp: {}",
                headers.timestamp
            ))
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let diff = (now - ts).abs();
        if diff > 300 {
            return Err(WxPayError::NotifyError(format!(
                "notification timestamp too old or too new: diff={diff}s"
            )));
        }

        debug!(serial = %headers.serial, "verifying notification signature");

        // Verify signature
        let mgr = self.cert_manager.read().await;
        let cert = mgr
            .get_cert(&headers.serial)
            .ok_or_else(|| {
                WxPayError::NotifyError(format!(
                    "platform certificate not found for serial: {}",
                    headers.serial
                ))
            })?;

        let valid = verify_signature(
            &cert.verifying_key,
            &headers.timestamp,
            &headers.nonce,
            body,
            &headers.signature,
        )?;

        if !valid {
            return Err(WxPayError::NotifyError(
                "notification signature verification failed".into(),
            ));
        }

        serde_json::from_str(body).map_err(|e| {
            WxPayError::NotifyError(format!("deserialize notification: {e}"))
        })
    }

    /// Decrypt a notification resource's ciphertext using api_v3_key.
    ///
    /// Returns the decrypted JSON string.
    pub fn decrypt_notify_resource(
        &self,
        resource: &NotifyResource,
    ) -> Result<String, WxPayError> {
        decrypt_aes_256_gcm(
            &self.config.api_v3_key,
            &resource.nonce,
            &resource.associated_data,
            &resource.ciphertext,
        )
    }

    /// Parse and verify a transaction notification, returning the decrypted data.
    pub async fn parse_transaction_notify(
        &self,
        headers: &NotifyHeaders,
        body: &str,
    ) -> Result<TransactionNotify, WxPayError> {
        let envelope = self.parse_notify(headers, body).await?;
        let json = self.decrypt_notify_resource(&envelope.resource)?;
        serde_json::from_str(&json).map_err(|e| {
            WxPayError::NotifyError(format!("deserialize transaction notify: {e}"))
        })
    }

    /// Parse and verify a refund notification, returning the decrypted data.
    pub async fn parse_refund_notify(
        &self,
        headers: &NotifyHeaders,
        body: &str,
    ) -> Result<RefundNotify, WxPayError> {
        let envelope = self.parse_notify(headers, body).await?;
        let json = self.decrypt_notify_resource(&envelope.resource)?;
        serde_json::from_str(&json).map_err(|e| {
            WxPayError::NotifyError(format!("deserialize refund notify: {e}"))
        })
    }
}
