use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rsa::{pkcs1v15::VerifyingKey, sha2::Sha256, signature::Verifier};

use crate::error::WxPayError;

/// Build the verification message for WeChat Pay responses/notifications.
///
/// Format: `"{timestamp}\n{nonce}\n{body}\n"`
pub fn build_verify_message(timestamp: &str, nonce: &str, body: &str) -> String {
    format!("{timestamp}\n{nonce}\n{body}\n")
}

/// Verify a WeChat Pay response/notification signature.
///
/// - `verifying_key`: cached RSA verifying key from the platform certificate
/// - `timestamp`: from `Wechatpay-Timestamp` header (or notification header)
/// - `nonce`: from `Wechatpay-Nonce` header
/// - `body`: response/notification body
/// - `signature_base64`: from `Wechatpay-Signature` header (base64-encoded)
pub fn verify_signature(
    verifying_key: &VerifyingKey<Sha256>,
    timestamp: &str,
    nonce: &str,
    body: &str,
    signature_base64: &str,
) -> Result<bool, WxPayError> {
    let message = build_verify_message(timestamp, nonce, body);

    let sig_bytes = BASE64
        .decode(signature_base64)
        .map_err(|e| WxPayError::VerifyError(format!("base64 decode: {e}")))?;

    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| WxPayError::VerifyError(format!("invalid signature: {e}")))?;

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::sign_sha256_rsa;
    use rsa::RsaPrivateKey;
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::SigningKey;

    #[test]
    fn test_verify_roundtrip() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let timestamp = "1554208460";
        let nonce = "test_nonce_str";
        let body = r#"{"code":"SUCCESS"}"#;

        let message = build_verify_message(timestamp, nonce, body);
        let sig = sign_sha256_rsa(&signing_key, &message).unwrap();

        let valid = verify_signature(&verifying_key, timestamp, nonce, body, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_tampered_body() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let timestamp = "1554208460";
        let nonce = "test_nonce_str";
        let body = r#"{"code":"SUCCESS"}"#;

        let message = build_verify_message(timestamp, nonce, body);
        let sig = sign_sha256_rsa(&signing_key, &message).unwrap();

        let tampered_body = r#"{"code":"FAIL"}"#;
        let valid =
            verify_signature(&verifying_key, timestamp, nonce, tampered_body, &sig).unwrap();
        assert!(!valid);
    }
}
