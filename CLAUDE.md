# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**wxp** is a pure Rust WeChat Pay V3 API SDK (library crate, not a binary). It provides async client functionality for payment creation, order management, refunds, bill downloads, and webhook notification handling. All cryptography is pure Rust (no OpenSSL).

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

- **API methods** are added by implementing `impl WxPayClient` in separate `api/` files — extend APIs by adding new files following this pattern.
- **Builder pattern** for `ClientConfig`: requires `mch_id`, `serial_no`, `api_v3_key` (must be 32 bytes), `private_key_pem` (PKCS1 or PKCS8).
- **All public methods** return `Result<T, WxPayError>`.
- **Certificate auto-refresh**: platform certs are fetched from `/v3/certificates`, decrypted with `api_v3_key`, cached in-memory, and refreshed every 12 hours via double-checked locking with `Arc<RwLock<>>`.
- **Request flow**: build sign message → SHA256withRSA sign → set `Authorization` header → send → verify response signature with platform cert → deserialize.
- **Notification flow**: verify signature → check timestamp freshness (±5 min) → AES-256-GCM decrypt `resource.ciphertext` → deserialize.

### Tests

Tests are inline `#[cfg(test)]` modules within source files, primarily covering crypto operations (sign/verify roundtrips, decrypt/encrypt roundtrips, tamper detection). Tests generate real RSA keys — no mocking framework.
