use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

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

    String::from_utf8(plaintext).map_err(|e| WxPayError::DecryptError(format!("utf8 decode: {e}")))
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

    #[test]
    fn test_decrypt_invalid_base64_ciphertext() {
        let key = "01234567890123456789012345678901";
        let nonce_str = "0123456789ab";
        let result = decrypt_aes_256_gcm(key, nonce_str, "", "not-valid-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = "01234567890123456789012345678901";
        let nonce_str = "0123456789ab";
        let aad = "certificate";
        let plaintext = r#"{"mchid":"1900000001"}"#;

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let gcm_nonce = Nonce::from_slice(nonce_str.as_bytes());
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        let mut ciphertext = cipher.encrypt(gcm_nonce, payload).unwrap();

        // Tamper with a byte
        ciphertext[0] ^= 0xFF;
        let ciphertext_b64 = BASE64.encode(&ciphertext);

        let result = decrypt_aes_256_gcm(key, nonce_str, aad, &ciphertext_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decrypt"));
    }

    #[test]
    fn test_decrypt_wrong_associated_data() {
        let key = "01234567890123456789012345678901";
        let nonce_str = "0123456789ab";
        let plaintext = r#"{"mchid":"1900000001"}"#;

        // Encrypt with correct AAD
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let gcm_nonce = Nonce::from_slice(nonce_str.as_bytes());
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: b"correct_aad",
        };
        let ciphertext = cipher.encrypt(gcm_nonce, payload).unwrap();
        let ciphertext_b64 = BASE64.encode(&ciphertext);

        // Decrypt with wrong AAD — GCM authentication must fail
        let result = decrypt_aes_256_gcm(key, nonce_str, "wrong_aad", &ciphertext_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key = "01234567890123456789012345678901";
        let wrong_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let nonce_str = "0123456789ab";
        let aad = "certificate";
        let plaintext = r#"{"mchid":"1900000001"}"#;

        // Encrypt with correct key
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let gcm_nonce = Nonce::from_slice(nonce_str.as_bytes());
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        let ciphertext = cipher.encrypt(gcm_nonce, payload).unwrap();
        let ciphertext_b64 = BASE64.encode(&ciphertext);

        // Decrypt with wrong key
        let result = decrypt_aes_256_gcm(wrong_key, nonce_str, aad, &ciphertext_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_empty_associated_data() {
        let key = "01234567890123456789012345678901";
        let nonce_str = "0123456789ab";
        let plaintext = r#"{"data":"test"}"#;

        // Encrypt with empty AAD (some notifications have empty associated_data)
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let gcm_nonce = Nonce::from_slice(nonce_str.as_bytes());
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: b"",
        };
        let ciphertext = cipher.encrypt(gcm_nonce, payload).unwrap();
        let ciphertext_b64 = BASE64.encode(&ciphertext);

        let decrypted = decrypt_aes_256_gcm(key, nonce_str, "", &ciphertext_b64).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
