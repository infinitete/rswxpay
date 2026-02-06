# rswxpay

[![CI](https://github.com/infinitete/rswxpay/actions/workflows/ci.yml/badge.svg)](https://github.com/infinitete/rswxpay/actions/workflows/ci.yml)

纯 Rust 实现的微信支付 V3 API SDK。

## 功能

- JSAPI / Native / H5 / App 四种支付方式下单
- 订单查询（商户订单号 / 微信交易号）、关闭订单
- 申请退款、退款查询
- 交易账单、资金账单下载
- 支付回调通知验签与解密（交易通知 / 退款通知）
- 平台证书自动下载与缓存（12 小时自动刷新）
- 小程序 / App 调起支付参数签名
- 敏感字段（私钥、API v3 密钥）内存安全清零

## 依赖

- 异步运行时：`tokio`
- HTTP 客户端：`reqwest` (rustls-tls)
- 签名/验签：`rsa` (PKCS1v15 + SHA256)
- 通知解密：`aes-gcm` (AES-256-GCM)
- 证书解析：`x509-cert`
- 序列化：`serde` + `serde_json`
- 内存安全：`zeroize`（敏感字段销毁时清零）

## 快速开始

```rust
use rswxpay::{ClientConfig, WxPayClient};
use rswxpay::model::common::{Amount, Payer};
use rswxpay::model::prepay::JsapiPrepayRequest;

#[tokio::main]
async fn main() -> Result<(), rswxpay::WxPayError> {
    let config = ClientConfig::builder()
        .mch_id("1900000001")
        .serial_no("YOUR_SERIAL_NO")
        .api_v3_key("your-32-byte-api-v3-key-here!!!!")
        .private_key_pem(include_str!("apiclient_key.pem"))
        .build()?;

    let client = WxPayClient::new(config).await?;

    // JSAPI 下单
    let resp = client.jsapi_prepay(&JsapiPrepayRequest {
        appid: "wxd678efh567hg6787".into(),
        mchid: "1900000001".into(),
        description: "商品描述".into(),
        out_trade_no: "ORDER_20240101_001".into(),
        time_expire: None,
        notify_url: "https://example.com/notify".into(),
        amount: Amount { total: 100, currency: None },
        payer: Payer { openid: "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o".into() },
        detail: None,
        scene_info: None,
        settle_info: None,
        attach: None,
        goods_tag: None,
        support_fapiao: None,
    }).await?;

    // 生成小程序调起支付参数
    let pay_params = client.build_jsapi_pay_params(
        "wxd678efh567hg6787",
        &resp.prepay_id,
    )?;
    println!("{}", serde_json::to_string(&pay_params).unwrap());

    Ok(())
}
```

## API 一览

### 下单

```rust
client.jsapi_prepay(&req).await?;   // JSAPI（小程序/公众号）
client.native_prepay(&req).await?;  // Native（扫码支付）
client.h5_prepay(&req).await?;      // H5
client.app_prepay(&req).await?;     // App
```

### 调起支付参数签名

```rust
client.build_jsapi_pay_params(appid, prepay_id)?;  // 小程序/JSAPI
client.build_app_pay_params(appid, prepay_id)?;     // App
```

### 订单

```rust
client.query_order_by_out_trade_no("ORDER_001").await?;
client.query_order_by_transaction_id("4200001234").await?;
client.close_order("ORDER_001").await?;
```

### 退款

```rust
client.create_refund(&req).await?;
client.query_refund("REFUND_001").await?;
```

### 账单

```rust
let bill = client.get_trade_bill(&req).await?;
let data = client.download_bill(&bill.download_url).await?;

let bill = client.get_fund_flow_bill(&req).await?;
```

### 回调通知

```rust
use rswxpay::model::notify::NotifyHeaders;

let headers = NotifyHeaders {
    timestamp: /* Wechatpay-Timestamp */,
    nonce: /* Wechatpay-Nonce */,
    signature: /* Wechatpay-Signature */,
    serial: /* Wechatpay-Serial */,
};

// 交易通知
let tx = client.parse_transaction_notify(&headers, &body).await?;

// 退款通知
let refund = client.parse_refund_notify(&headers, &body).await?;
```

## 模块结构

```
rswxpay/src/
├── lib.rs              公开导出
├── client.rs           WxPayClient（签名 HTTP、响应验签）
├── config.rs           ClientConfig + Builder
├── error.rs            WxPayError
├── notify.rs           回调通知处理
├── crypto/
│   ├── sign.rs         请求签名（SHA256withRSA）
│   ├── verify.rs       响应验签
│   └── decrypt.rs      AES-256-GCM 解密
├── cert/
│   ├── store.rs        平台证书内存缓存
│   └── manager.rs      证书自动下载与刷新
├── api/
│   ├── prepay.rs       下单接口
│   ├── order.rs        订单查询/关闭
│   ├── refund.rs       退款接口
│   └── bill.rs         账单接口
└── model/
    ├── common.rs       公共类型（Amount, Payer, SceneInfo 等）
    ├── prepay.rs       下单请求/响应 + 调起支付参数
    ├── order.rs        订单查询响应
    ├── refund.rs       退款请求/响应
    ├── bill.rs         账单请求/响应
    ├── notify.rs       通知信封 + 解密后数据
    └── cert.rs         证书接口响应
```

## 安全设计

- 纯 Rust 加密实现，不依赖 OpenSSL
- 所有 HTTP 响应强制验签（fail-closed），证书存储非空时缺少签名头即报错
- 回调通知验签 + 时间戳新鲜度检查（±5 分钟窗口）
- AES-256-GCM 解密使用 AAD（附加认证数据），防篡改
- `ClientConfig` 销毁时自动清零 `api_v3_key` 和 `private_key_pem`
- `api_v3_key` 强制 32 字节 ASCII 校验
- URL 路径参数全部 percent-encoding，防注入
- RSA 签名使用 `spawn_blocking`，避免阻塞异步运行时

## 构建与测试

```bash
cargo build
cargo clippy
cargo test     # 53 个单元测试
```
