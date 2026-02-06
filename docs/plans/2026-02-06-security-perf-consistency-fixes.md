# wxp Security, Performance & Consistency Fixes

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all security vulnerabilities, performance bottlenecks, and implementation inconsistencies identified in the wxp WeChat Pay SDK review.

**Architecture:** Targeted fixes across 8 source files. Security fixes harden signature verification and add replay protection. Performance fixes cache cryptographic keys to avoid per-request cloning. Consistency fixes unify timestamp helpers, remove dead code, and align error handling.

**Tech Stack:** Rust 2024, rsa 0.9, aes-gcm 0.10, tokio, reqwest

---

### Task 1: Enforce response signature verification (security — high)

**Files:**
- Modify: `src/client.rs:209-243` (`verify_and_read`)
- Modify: `src/client.rs:93-110` (`post_no_content`)
- Modify: `src/client.rs:123-165` (`get_bytes`)

**Problem:** `verify_and_read` silently skips verification when signature headers are missing or cert is not found. `post_no_content` and `get_bytes` skip verification entirely.

**Step 1: Harden `verify_and_read` — require signature headers**

In `src/client.rs`, replace the `verify_and_read` method body so that:
- Missing signature headers → return `WxPayError::VerifyError`
- Unknown cert serial → return `WxPayError::VerifyError`
- Only allow skipping when cert store is empty (bootstrap `/v3/certificates` call)

```rust
async fn verify_and_read(&self, resp: reqwest::Response) -> Result<String, WxPayError> {
    let status = resp.status();

    let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
    let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
    let wechat_signature = header_str(&resp, "Wechatpay-Signature");
    let wechat_serial = header_str(&resp, "Wechatpay-Serial");

    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return self.parse_api_error(&body);
    }

    match (&wechat_timestamp, &wechat_nonce, &wechat_signature, &wechat_serial) {
        (Some(ts), Some(nonce), Some(sig), Some(serial)) => {
            let mgr = self.cert_manager.read().await;
            if let Some(cert) = mgr.get_cert(serial) {
                let valid = verify_signature(&cert.public_key, ts, nonce, &body, sig)?;
                if !valid {
                    return Err(WxPayError::VerifyError(
                        "response signature verification failed".into(),
                    ));
                }
            } else if !mgr.is_empty() {
                return Err(WxPayError::VerifyError(format!(
                    "platform certificate not found for serial: {serial}"
                )));
            }
            // cert store empty = bootstrap, skip
        }
        _ => {
            let mgr = self.cert_manager.read().await;
            if !mgr.is_empty() {
                return Err(WxPayError::VerifyError(
                    "response missing signature headers".into(),
                ));
            }
        }
    }

    Ok(body)
}
```

**Step 2: Add signature verification to `post_no_content`**

Replace `post_no_content` to use `verify_and_read` style verification for the headers, even though body is empty for 204:

```rust
pub(crate) async fn post_no_content<Req>(
    &self,
    path: &str,
    body: &Req,
) -> Result<(), WxPayError>
where
    Req: serde::Serialize,
{
    let body_str = serde_json::to_string(body)?;
    let resp = self.do_request("POST", path, &body_str).await?;
    let status = resp.status();

    let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
    let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
    let wechat_signature = header_str(&resp, "Wechatpay-Signature");
    let wechat_serial = header_str(&resp, "Wechatpay-Serial");

    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return self.parse_api_error(&body);
    }

    if let (Some(ts), Some(nonce), Some(sig), Some(serial)) = (
        &wechat_timestamp,
        &wechat_nonce,
        &wechat_signature,
        &wechat_serial,
    ) {
        let mgr = self.cert_manager.read().await;
        if let Some(cert) = mgr.get_cert(serial) {
            let valid = verify_signature(&cert.public_key, ts, nonce, &body, sig)?;
            if !valid {
                return Err(WxPayError::VerifyError(
                    "response signature verification failed".into(),
                ));
            }
        }
    }

    Ok(())
}
```

**Step 3: Add signature verification to `get_bytes`**

After the success check in `get_bytes`, add header verification before returning bytes. Extract headers before consuming the response:

```rust
pub(crate) async fn get_bytes(&self, url: &str) -> Result<bytes::Bytes, WxPayError> {
    // ... (existing URL/path logic unchanged) ...

    let resp = self
        .http
        .get(&full_url)
        .header("Authorization", &auth)
        .header("Accept", "application/json")
        .header("User-Agent", "wxp-rust-sdk/0.1.0")
        .send()
        .await?;

    let wechat_timestamp = header_str(&resp, "Wechatpay-Timestamp");
    let wechat_nonce = header_str(&resp, "Wechatpay-Nonce");
    let wechat_signature = header_str(&resp, "Wechatpay-Signature");
    let wechat_serial = header_str(&resp, "Wechatpay-Serial");

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return self.parse_api_error(&body);
    }

    let data = resp.bytes().await.map_err(WxPayError::Http)?;

    // Verify signature against raw body bytes interpreted as UTF-8 (or lossy)
    if let (Some(ts), Some(nonce), Some(sig), Some(serial)) = (
        &wechat_timestamp,
        &wechat_nonce,
        &wechat_signature,
        &wechat_serial,
    ) {
        let body_str = String::from_utf8_lossy(&data);
        let mgr = self.cert_manager.read().await;
        if let Some(cert) = mgr.get_cert(serial) {
            let valid = verify_signature(&cert.public_key, ts, nonce, &body_str, sig)?;
            if !valid {
                return Err(WxPayError::VerifyError(
                    "response signature verification failed".into(),
                ));
            }
        }
    }

    Ok(data)
}
```

**Step 4: Run tests**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test`
Expected: all 9 existing tests pass, no new compile errors.

**Step 5: Run clippy**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo clippy`
Expected: no warnings.

---

### Task 2: Add notification timestamp replay protection (security — high)

**Files:**
- Modify: `src/notify.rs:14-49` (`parse_notify`)

**Problem:** `parse_notify` verifies signature but never checks if the notification timestamp is within a reasonable window. Old notifications can be replayed.

**Step 1: Add timestamp validation to `parse_notify`**

After the signature verification succeeds and before deserializing, add a check:

```rust
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
        &cert.public_key,
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
```

**Step 2: Run tests**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test`
Expected: all tests pass.

---

### Task 3: Cache signing/verifying keys to avoid per-request clone (performance)

**Files:**
- Modify: `src/client.rs:13-18` (WxPayClient struct)
- Modify: `src/client.rs:24-49` (`WxPayClient::new`)
- Modify: `src/crypto/sign.rs:31-39` (`sign_sha256_rsa`)
- Modify: `src/cert/store.rs:7-13` (PlatformCert struct)
- Modify: `src/cert/manager.rs:82-105` (cert push logic)

**Problem:** `sign_sha256_rsa` clones `RsaPrivateKey` on every call. `verify_signature` clones `RsaPublicKey` on every call.

**Step 1: Add `SigningKey` to `WxPayClient`**

```rust
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;

pub struct WxPayClient {
    pub(crate) config: ClientConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) private_key: RsaPrivateKey,
    pub(crate) signing_key: SigningKey<Sha256>,
    pub(crate) cert_manager: Arc<RwLock<PlatformCertManager>>,
}
```

In `WxPayClient::new`, after parsing the private key:

```rust
let signing_key = SigningKey::<Sha256>::new(private_key.clone());
```

**Step 2: Update `sign_sha256_rsa` to accept `&SigningKey<Sha256>`**

```rust
pub fn sign_sha256_rsa(
    signing_key: &SigningKey<Sha256>,
    message: &str,
) -> Result<String, WxPayError> {
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, message.as_bytes());
    Ok(BASE64.encode(signature.to_bytes()))
}
```

Update all call sites in `client.rs`, `api/prepay.rs`, and `cert/manager.rs` to pass `&self.signing_key` instead of `&self.private_key`.

For `cert/manager.rs::refresh`, accept `&SigningKey<Sha256>` instead of `&RsaPrivateKey`.

**Step 3: Add `VerifyingKey` to `PlatformCert`**

```rust
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
```

In `cert/manager.rs`, when building `PlatformCert`:

```rust
let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
certs.push(PlatformCert {
    serial_no: data.serial_no.clone(),
    effective_time: data.effective_time.clone(),
    expire_time: data.expire_time.clone(),
    public_key,
    verifying_key,
    certificate_pem: pem_str,
});
```

**Step 4: Update `verify_signature` to accept `&VerifyingKey<Sha256>`**

```rust
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
```

Update all call sites in `client.rs` and `notify.rs` to pass `&cert.verifying_key`.

**Step 5: Update tests**

Update `crypto/sign.rs` tests and `crypto/verify.rs` tests to use the new signatures.

**Step 6: Run tests and clippy**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test && cargo clippy`
Expected: all pass.

---

### Task 4: Unify timestamp helper and remove dead code (consistency)

**Files:**
- Modify: `src/client.rs:261-266` (move `current_timestamp` to shared location)
- Modify: `src/api/prepay.rs:100-106` (remove `current_timestamp_str`)
- Modify: `src/cert/manager.rs:50-53` (use shared helper)
- Modify: `src/cert/store.rs:32-34` (remove `get_latest`)

**Step 1: Move `current_timestamp` to a shared util**

Create a `pub(crate) fn current_timestamp() -> i64` at the top of `client.rs` (or keep it there as `pub(crate)`). Add a `pub(crate) fn current_timestamp_str() -> String` wrapper. Remove the duplicate in `api/prepay.rs`.

In `client.rs`, change `fn current_timestamp()` to:
```rust
pub(crate) fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub(crate) fn current_timestamp_str() -> String {
    current_timestamp().to_string()
}
```

In `api/prepay.rs`, remove the local `fn current_timestamp_str()` and import:
```rust
use crate::client::{current_timestamp_str};
```

In `cert/manager.rs`, import and use:
```rust
use crate::client::current_timestamp;
```
Replace lines 50-53 with `let timestamp = current_timestamp();`.

**Step 2: Remove unused `get_latest`**

Remove `get_latest` from `src/cert/store.rs:32-34` — it's never called and its semantics are misleading (HashMap ordering is arbitrary).

**Step 3: Run tests and clippy**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test && cargo clippy`
Expected: all pass.

---

### Task 5: URL-encode path parameters (security — medium)

**Files:**
- Modify: `src/api/order.rs`
- Modify: `src/api/refund.rs`
- Modify: `src/api/bill.rs`

**Problem:** User-controlled strings are interpolated into URL paths without encoding.

**Step 1: Add `percent-encoding` dependency**

In `Cargo.toml` add:
```toml
percent-encoding = "2"
```

**Step 2: Encode path segments and query values**

In `src/api/order.rs`:
```rust
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

fn encode_path(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}
```

Then use `encode_path(out_trade_no)` in format strings for path segments. Keep `self.config.mch_id` unencoded (trusted internal value).

Apply the same pattern in `refund.rs` and `bill.rs`.

**Step 3: Run tests and clippy**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test && cargo clippy`
Expected: all pass.

---

### Task 6: Add tracing logs to key operations (consistency)

**Files:**
- Modify: `src/client.rs` (do_request, verify_and_read, ensure_certs)
- Modify: `src/cert/manager.rs` (refresh)
- Modify: `src/notify.rs` (parse_notify)

**Problem:** `tracing` is a dependency but never used.

**Step 1: Add trace/debug/warn logs**

In `client.rs`:
```rust
use tracing::{debug, warn};

// In ensure_certs, before refresh:
debug!("refreshing platform certificates");

// In do_request:
debug!(method, path, "sending signed request");

// In verify_and_read, on verification failure or skip:
warn!("response missing signature headers");
warn!(serial, "platform certificate not found for serial");
```

In `cert/manager.rs::refresh`:
```rust
use tracing::{debug, info};
debug!("fetching platform certificates from {}", url);
info!(count = certs.len(), "platform certificates updated");
```

In `notify.rs::parse_notify`:
```rust
use tracing::debug;
debug!(event_type = %headers.serial, "verifying notification");
```

**Step 2: Run tests and clippy**

Run: `cd /home/renshan/Projects/Workspace/Account/wxp && cargo test && cargo clippy`
Expected: all pass.

---

## Summary of Changes

| Task | Category | Severity | Files Changed |
|------|----------|----------|---------------|
| 1 | Security | High | client.rs |
| 2 | Security | High | notify.rs |
| 3 | Performance | Medium | client.rs, sign.rs, verify.rs, store.rs, manager.rs |
| 4 | Consistency | Low | client.rs, prepay.rs, manager.rs, store.rs |
| 5 | Security | Medium | order.rs, refund.rs, bill.rs, Cargo.toml |
| 6 | Consistency | Low | client.rs, manager.rs, notify.rs |
