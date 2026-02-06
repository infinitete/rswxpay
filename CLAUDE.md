# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rswxpay** is a pure Rust WeChat Pay V3 API SDK (library crate, not a binary). It provides async client functionality for payment creation, order management, refunds, bill downloads, and webhook notification handling. All cryptography is pure Rust (no OpenSSL).

## Commands

```bash
cargo build           # Build
cargo test            # All tests
cargo test test_name  # Single test
cargo clippy          # Lint
cargo fmt             # Format
```

No workspace — single crate. Uses Rust **edition 2024**.

## Architecture

```
WxPayClient (client.rs)          ← Facade: signed HTTP requests + response verification
  ├── api/*                      ← API methods as `impl WxPayClient` blocks
  │   ├── prepay.rs              ← JSAPI/Native/H5/App payment creation
  │   ├── order.rs               ← Query/close orders
  │   ├── refund.rs              ← Create/query refunds
  │   └── bill.rs                ← Trade/fund bill downloads
  ├── crypto/*                   ← Cryptographic operations
  │   ├── sign.rs                ← SHA256withRSA request signing
  │   ├── verify.rs              ← RSA signature verification
  │   └── decrypt.rs             ← AES-256-GCM decryption (notifications)
  ├── cert/*                     ← Platform certificate management
  │   ├── manager.rs             ← Auto-download & 12-hour refresh
  │   └── store.rs               ← In-memory cache (HashMap + RwLock)
  ├── config.rs                  ← ClientConfig builder pattern
  ├── error.rs                   ← WxPayError enum (thiserror)
  ├── notify.rs                  ← Webhook notification parsing
  └── model/*                    ← Serde request/response types
```

### Key Patterns

- **Builder pattern** for `ClientConfig`: requires `mch_id`, `serial_no`, `api_v3_key` (must be 32 ASCII bytes), `private_key_pem` (PKCS1 or PKCS8). Fields are `pub(crate)` with public getters (`mch_id()`, `serial_no()`, `base_url()`).
- **Sensitive field protection**: `ClientConfig` implements `Drop` to zeroize `api_v3_key` and `private_key_pem` on destruction (via `zeroize` crate). `api_v3_key` is validated to be ASCII-only.
- **All public methods** return `Result<T, WxPayError>`.
- **Certificate auto-refresh**: platform certs are fetched from `/v3/certificates` via standalone `fetch_platform_certs()`, decrypted with `api_v3_key`, cached in-memory, and refreshed every 12 hours. Uses `AtomicU64` for a lock-free fast path — most requests skip the `RwLock` entirely. HTTP fetch runs outside the lock; write lock is only held briefly to swap the cert store.
- **Non-blocking RSA signing**: `do_request()` and `get_bytes()` use `tokio::task::spawn_blocking` for RSA-2048 PKCS1v15 signing (~1-3ms), preventing async runtime thread starvation under high concurrency. `signing_key` is `Arc<SigningKey<Sha256>>` for cheap cloning into the blocking closure.
- **Unified response verification**: all HTTP methods (`post`, `post_no_content`, `get`, `get_bytes`) use `verify_response_signature()` — a single method that enforces consistent signature checking (fail-closed when cert store is populated, skip during bootstrap). Bootstrap skip is safe because AES-GCM decryption of the certificate response provides implicit authentication via `api_v3_key`.
- **Request flow**: build sign message → SHA256withRSA sign (spawn_blocking) → set `Authorization` header → send → verify response signature with platform cert → deserialize.
- **Notification flow**: verify signature → check timestamp freshness (±5 min) → AES-256-GCM decrypt `resource.ciphertext` → deserialize.
- **`verify_signature()`** returns `Ok(bool)` (not `Err` on mismatch) — callers check the bool.

### Adding a New API

1. Add request/response model types in `model/` with `Serialize`/`Deserialize` derives. Use `#[serde(skip_serializing_if = "Option::is_none")]` on optional fields.
2. Add a new file under `api/` with an `impl WxPayClient` block. Delegate to `self.post()`, `self.get()`, `self.post_no_content()`, or `self.get_bytes()` as appropriate.
3. Register the new module in `api/mod.rs` and `model/mod.rs`.
4. URL-encode any user-controlled path/query segments using `crate::client::encode_path_segment()`.

### Core Internal Methods (client.rs)

- `post<Req, Resp>()` — POST with JSON body, returns deserialized response
- `post_no_content<Req>()` — POST expecting 204 (e.g., close order)
- `get<Resp>()` — GET returning deserialized response
- `get_bytes()` — GET returning raw `bytes::Bytes` (bill downloads)
- `verify_response_signature()` — unified response signature verification
- `encode_path_segment()` — shared URL percent-encoding helper
- `ensure_certs()` — atomic fast-path cert freshness check + refresh

### Core Internal Functions (cert/manager.rs)

- `fetch_platform_certs()` — standalone async function: signs request, fetches `/v3/certificates`, decrypts and parses certs. Designed to run outside any lock.

### Tests

Tests are inline `#[cfg(test)]` modules within source files (53 tests total):
- **crypto/sign.rs** (4): message building, authorization header, sign+verify roundtrip
- **crypto/verify.rs** (7): message format, roundtrip, tampered body/timestamp, invalid base64, wrong key
- **crypto/decrypt.rs** (8): roundtrip, invalid key/nonce length, invalid base64, tampered ciphertext, wrong AAD/key, empty AAD
- **config.rs** (12): builder validation, required fields, key length, ASCII validation, default/custom base URL, getters, zeroize behavior
- **client.rs** (12): `extract_path` URL parsing (6), `encode_path_segment` encoding (4), timestamp sanity (2)
- **cert/store.rs** (9): empty/default store, update/get, unknown serial, replace-all, multiple certs, refresh logic, clear on empty update

Tests generate real RSA 2048-bit keys at runtime — no mocking framework.
