use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::error::WxPayError;

/// Decrypt a WeChat Pay notification/certificate resource ciphertext using AES-256-GCM.
///
/// - `api_v3_key`: 32-byte UTF-8 string used directly as the AES key
/// - `nonce`: from `resource.nonce` (12 bytes)
/// - `associated_data`: from `resource.associated_data`
/// - `ciphertext_base64`: from `resource.ciphertext` (base64-encoded)
///
/// Returns the decrypted plaintext as a UTF-8 string.
pub fn decrypt_aes_256_gcm(
    api_v3_key: &str,
    nonce: &str,
    associated_data: &str,
    ciphertext_base64: &str,
) -> Result<String, WxPayError> {
    let key_bytes = api_v3_key.as_bytes();
    if key_bytes.len() != 32 {
        return Err(WxPayError::DecryptError(format!(
            "api_v3_key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let nonce_bytes = nonce.as_bytes();
    if nonce_bytes.len() != 12 {
        return Err(WxPayError::DecryptError(format!(
            "nonce must be 12 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let ciphertext = BASE64
        .decode(ciphertext_base64)
        .map_err(|e| WxPayError::DecryptError(format!("base64 decode: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| WxPayError::DecryptError(format!("create cipher: {e}")))?;

    let gcm_nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: &ciphertext,
        aad: associated_data.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(gcm_nonce, payload)
        .map_err(|e| WxPayError::DecryptError(format!("decrypt: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| WxPayError::DecryptError(format!("utf8 decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = "01234567890123456789012345678901"; // 32 bytes
        let nonce_str = "0123456789ab"; // 12 bytes
        let aad = "certificate";
        let plaintext = r#"{"mchid":"1900000001"}"#;

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let gcm_nonce = Nonce::from_slice(nonce_str.as_bytes());
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        let ciphertext = cipher.encrypt(gcm_nonce, payload).unwrap();
        let ciphertext_b64 = BASE64.encode(&ciphertext);

        // Decrypt
        let decrypted = decrypt_aes_256_gcm(key, nonce_str, aad, &ciphertext_b64).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = decrypt_aes_256_gcm("short_key", "0123456789ab", "", "dGVzdA==");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = "01234567890123456789012345678901";
        let result = decrypt_aes_256_gcm(key, "short", "", "dGVzdA==");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("12 bytes"));
    }
}
