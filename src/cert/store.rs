use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsa::pkcs1v15::VerifyingKey;
use rsa::sha2::Sha256;
use rsa::RsaPublicKey;

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
