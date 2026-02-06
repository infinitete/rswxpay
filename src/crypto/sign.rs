use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rsa::{
    pkcs1v15::SigningKey,
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding},
};

use crate::error::WxPayError;

/// Build the signing message per WeChat Pay V3 spec.
///
/// Format: `"{method}\n{url_path}\n{timestamp}\n{nonce}\n{body}\n"`
///
/// - `method`: HTTP method, e.g. "GET", "POST"
/// - `url_path`: absolute path with query string, e.g. "/v3/pay/transactions/jsapi"
/// - `timestamp`: Unix timestamp in seconds
/// - `nonce`: random string
/// - `body`: request body (empty string for GET)
pub fn build_sign_message(
    method: &str,
    url_path: &str,
    timestamp: i64,
    nonce: &str,
    body: &str,
) -> String {
    format!("{method}\n{url_path}\n{timestamp}\n{nonce}\n{body}\n")
}

/// Sign the message using SHA256withRSA (PKCS1v15) and return base64-encoded signature.
pub fn sign_sha256_rsa(
    signing_key: &SigningKey<Sha256>,
    message: &str,
) -> Result<String, WxPayError> {
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, message.as_bytes());
    Ok(BASE64.encode(signature.to_bytes()))
}

/// Build the complete Authorization header value.
///
/// Format: `WECHATPAY2-SHA256-RSA2048 mchid="...",nonce_str="...",timestamp="...",serial_no="...",signature="..."`
pub fn build_authorization_header(
    mch_id: &str,
    serial_no: &str,
    timestamp: i64,
    nonce: &str,
    signature: &str,
) -> String {
    format!(
        r#"WECHATPAY2-SHA256-RSA2048 mchid="{mch_id}",nonce_str="{nonce}",timestamp="{timestamp}",serial_no="{serial_no}",signature="{signature}""#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sign_message() {
        let msg = build_sign_message(
            "POST",
            "/v3/pay/transactions/jsapi",
            1554208460,
            "593BEC0C930BF1AFEB40B4A08C8FB242",
            "{\"appid\":\"wx1234\"}",
        );
        let expected = "POST\n/v3/pay/transactions/jsapi\n1554208460\n593BEC0C930BF1AFEB40B4A08C8FB242\n{\"appid\":\"wx1234\"}\n";
        assert_eq!(msg, expected);
    }

    #[test]
    fn test_build_sign_message_get() {
        let msg = build_sign_message("GET", "/v3/certificates", 1554208460, "nonce123", "");
        let expected = "GET\n/v3/certificates\n1554208460\nnonce123\n\n";
        assert_eq!(msg, expected);
    }

    #[test]
    fn test_build_authorization_header() {
        let header =
            build_authorization_header("1900000001", "SERIAL123", 1554208460, "nonce123", "sig==");
        assert!(header.starts_with("WECHATPAY2-SHA256-RSA2048 "));
        assert!(header.contains(r#"mchid="1900000001""#));
        assert!(header.contains(r#"serial_no="SERIAL123""#));
        assert!(header.contains(r#"timestamp="1554208460""#));
        assert!(header.contains(r#"nonce_str="nonce123""#));
        assert!(header.contains(r#"signature="sig==""#));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        use rsa::RsaPrivateKey;
        use rsa::RsaPublicKey;
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let message = "POST\n/v3/pay/transactions/jsapi\n1554208460\nnonce123\n{}\n";
        let sig_b64 = sign_sha256_rsa(&signing_key, message).unwrap();

        let sig_bytes = BASE64.decode(&sig_b64).unwrap();
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(message.as_bytes(), &signature).is_ok());
    }
}
