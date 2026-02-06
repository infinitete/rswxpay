use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CertificatesResponse {
    pub data: Vec<CertificateData>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateData {
    pub serial_no: String,
    pub effective_time: String,
    pub expire_time: String,
    pub encrypt_certificate: EncryptCertificate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptCertificate {
    pub algorithm: String,
    pub nonce: String,
    pub associated_data: String,
    pub ciphertext: String,
}
