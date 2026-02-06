use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsa::RsaPublicKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::sha2::Sha256;

#[derive(Clone)]
pub struct PlatformCert {
    pub serial_no: String,
    pub effective_time: String,
    pub expire_time: String,
    pub public_key: RsaPublicKey,
    pub verifying_key: VerifyingKey<Sha256>,
    pub certificate_pem: String,
}

pub struct InMemoryCertStore {
    certs: HashMap<String, PlatformCert>,
    last_updated: Option<Instant>,
}

impl InMemoryCertStore {
    pub fn new() -> Self {
        Self {
            certs: HashMap::new(),
            last_updated: None,
        }
    }

    pub fn get(&self, serial_no: &str) -> Option<&PlatformCert> {
        self.certs.get(serial_no)
    }

    pub fn update(&mut self, certs: Vec<PlatformCert>) {
        self.certs.clear();
        for cert in certs {
            self.certs.insert(cert.serial_no.clone(), cert);
        }
        self.last_updated = Some(Instant::now());
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    pub fn needs_refresh(&self, interval: Duration) -> bool {
        match self.last_updated {
            None => true,
            Some(t) => t.elapsed() >= interval,
        }
    }
}

impl Default for InMemoryCertStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;

    fn test_platform_cert(serial: &str) -> PlatformCert {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
        PlatformCert {
            serial_no: serial.to_string(),
            effective_time: "2024-01-01T00:00:00+08:00".to_string(),
            expire_time: "2029-01-01T00:00:00+08:00".to_string(),
            public_key,
            verifying_key,
            certificate_pem: "test-pem".to_string(),
        }
    }

    #[test]
    fn test_new_store_is_empty() {
        let store = InMemoryCertStore::new();
        assert!(store.is_empty());
        assert!(store.get("ANY").is_none());
    }

    #[test]
    fn test_default_store_is_empty() {
        let store = InMemoryCertStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn test_update_and_get() {
        let cert = test_platform_cert("SERIAL_A");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert]);

        assert!(!store.is_empty());
        let retrieved = store.get("SERIAL_A").unwrap();
        assert_eq!(retrieved.serial_no, "SERIAL_A");
    }

    #[test]
    fn test_get_unknown_serial() {
        let cert = test_platform_cert("SERIAL_A");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert]);

        assert!(store.get("SERIAL_B").is_none());
    }

    #[test]
    fn test_update_replaces_all() {
        let cert_a = test_platform_cert("SERIAL_A");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert_a]);
        assert!(store.get("SERIAL_A").is_some());

        // Second update replaces everything
        let cert_b = test_platform_cert("SERIAL_B");
        store.update(vec![cert_b]);
        assert!(store.get("SERIAL_A").is_none());
        assert!(store.get("SERIAL_B").is_some());
    }

    #[test]
    fn test_update_multiple_certs() {
        let cert_a = test_platform_cert("SERIAL_A");
        let cert_b = test_platform_cert("SERIAL_B");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert_a, cert_b]);

        assert!(store.get("SERIAL_A").is_some());
        assert!(store.get("SERIAL_B").is_some());
        assert!(store.get("SERIAL_C").is_none());
    }

    #[test]
    fn test_needs_refresh_initially() {
        let store = InMemoryCertStore::new();
        assert!(store.needs_refresh(Duration::from_secs(3600)));
        assert!(store.needs_refresh(Duration::ZERO));
    }

    #[test]
    fn test_needs_refresh_after_update() {
        let cert = test_platform_cert("SERIAL_A");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert]);

        // Long interval → should NOT need refresh right after update
        assert!(!store.needs_refresh(Duration::from_secs(3600)));
        // Zero interval → should always need refresh
        assert!(store.needs_refresh(Duration::ZERO));
    }

    #[test]
    fn test_update_with_empty_vec_clears_store() {
        let cert = test_platform_cert("SERIAL_A");
        let mut store = InMemoryCertStore::new();
        store.update(vec![cert]);
        assert!(!store.is_empty());

        store.update(vec![]);
        assert!(store.is_empty());
        assert!(store.get("SERIAL_A").is_none());
    }
}
