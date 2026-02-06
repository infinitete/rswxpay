# rswxpay

[![CI](https://github.com/infinitete/rswxpay/actions/workflows/ci.yml/badge.svg)](https://github.com/infinitete/rswxpay/actions/workflows/ci.yml)

纯 Rust 实现的微信支付 V3 API SDK。不依赖 OpenSSL，所有加密操作均使用纯 Rust 实现。

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

| 功能 | 依赖 | 说明 |
|------|------|------|
| 异步运行时 | `tokio` | async/await 支持 |
| HTTP 客户端 | `reqwest` | rustls-tls，纯 Rust TLS |
| 请求签名/验签 | `rsa` | PKCS1v15 + SHA256 |
| 通知解密 | `aes-gcm` | AES-256-GCM |
| 证书解析 | `x509-cert` | X.509 证书 DER/PEM 解析 |
| 序列化 | `serde` + `serde_json` | JSON 序列化/反序列化 |
| 内存安全 | `zeroize` | 敏感字段销毁时清零 |

## 快速开始

### 添加依赖

```toml
[dependencies]
rswxpay = "0.1"
tokio = { version = "1", features = ["full"] }
serde_json = "1"
```

### 初始化客户端

```rust
use rswxpay::{ClientConfig, WxPayClient};

let config = ClientConfig::builder()
    .mch_id("1900000001")                            // 商户号
    .serial_no("YOUR_SERIAL_NO")                     // 商户 API 证书序列号
    .api_v3_key("your-32-byte-api-v3-key-here!!!!")  // API v3 密钥（32 字节 ASCII）
    .private_key_pem(include_str!("apiclient_key.pem"))  // 商户私钥（PKCS1 或 PKCS8）
    .build()?;

let client = WxPayClient::new(config).await?;
```

`ClientConfig::builder()` 还支持以下可选配置：

```rust
ClientConfig::builder()
    .mch_id("1900000001")
    .serial_no("YOUR_SERIAL_NO")
    .api_v3_key("your-32-byte-api-v3-key-here!!!!")
    .private_key_pem(include_str!("apiclient_key.pem"))
    .base_url("https://api.mch.weixin.qq.com")  // 自定义 API 地址（默认值如左）
    .http_client(custom_reqwest_client)          // 自定义 reqwest::Client
    .build()?;
```

### JSAPI 下单示例

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

## API 参考

### 下单

```rust
// JSAPI（小程序/公众号）
let resp = client.jsapi_prepay(&req).await?;
// resp: JsapiPrepayResponse { prepay_id: String }

// Native（扫码支付）
let resp = client.native_prepay(&req).await?;
// resp: NativePrepayResponse { code_url: String }

// H5
let resp = client.h5_prepay(&req).await?;
// resp: H5PrepayResponse { h5_url: String }

// App
let resp = client.app_prepay(&req).await?;
// resp: AppPrepayResponse { prepay_id: String }
```

四种下单请求结构大致相同，必填字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `appid` | `String` | 应用 ID |
| `mchid` | `String` | 商户号 |
| `description` | `String` | 商品描述 |
| `out_trade_no` | `String` | 商户订单号 |
| `notify_url` | `String` | 回调通知地址 |
| `amount` | `Amount` | 订单金额（`total` 单位：分） |

JSAPI 额外必填 `payer: Payer { openid }`，H5 额外必填 `scene_info: SceneInfo`。

### 调起支付参数签名

```rust
// 小程序 / JSAPI — 返回 JsapiPayParams
let params = client.build_jsapi_pay_params("wx_appid", &prepay_id)?;

// App — 返回 AppPayParams
let params = client.build_app_pay_params("wx_appid", &prepay_id)?;
```

返回的参数可直接序列化为 JSON 传给前端/客户端调起支付。

### 订单查询与关闭

```rust
// 通过商户订单号查询
let order = client.query_order_by_out_trade_no("ORDER_001").await?;

// 通过微信交易号查询
let order = client.query_order_by_transaction_id("4200001234").await?;

// 关闭订单（返回 ()，HTTP 204）
client.close_order("ORDER_001").await?;
```

`OrderQueryResponse` 主要字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `trade_state` | `String` | 交易状态：SUCCESS / REFUND / NOTPAY / CLOSED / ... |
| `trade_state_desc` | `String` | 状态描述 |
| `transaction_id` | `Option<String>` | 微信支付订单号 |
| `amount` | `Option<OrderAmount>` | 金额信息（含 `total`、`payer_total`） |
| `payer` | `Option<Payer>` | 支付者信息 |

### 退款

```rust
use rswxpay::model::refund::{RefundRequest, RefundAmount};

// 申请退款
let refund = client.create_refund(&RefundRequest {
    transaction_id: Some("4200001234".into()),
    out_trade_no: None,
    out_refund_no: "REFUND_001".into(),
    reason: Some("商品退货".into()),
    notify_url: Some("https://example.com/refund_notify".into()),
    amount: RefundAmount {
        refund: 50,
        total: 100,
        currency: "CNY".into(),
        from: None,
    },
    funds_account: None,
    goods_detail: None,
}).await?;

// 查询退款
let refund = client.query_refund("REFUND_001").await?;
```

`RefundResponse` 主要字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `refund_id` | `String` | 微信退款单号 |
| `status` | `String` | 退款状态：SUCCESS / PROCESSING / ABNORMAL / CLOSED |
| `channel` | `String` | 退款渠道 |
| `user_received_account` | `String` | 退款入账账户 |

### 账单下载

```rust
use rswxpay::model::bill::{TradeBillRequest, FundFlowBillRequest};

// 获取交易账单下载地址
let bill = client.get_trade_bill(&TradeBillRequest {
    bill_date: "2024-01-01".into(),
    bill_type: None,    // ALL / SUCCESS / REFUND（默认 ALL）
    tar_type: None,     // GZIP（默认不压缩）
}).await?;

// 获取资金账单下载地址
let bill = client.get_fund_flow_bill(&FundFlowBillRequest {
    bill_date: "2024-01-01".into(),
    account_type: None, // BASIC / OPERATION / FEES（默认 BASIC）
    tar_type: None,
}).await?;

// 下载账单文件（返回 bytes::Bytes）
let data = client.download_bill(&bill.download_url).await?;
```

### 回调通知

从 HTTP 请求头中提取验签所需字段，然后解析通知内容：

```rust
use rswxpay::model::notify::NotifyHeaders;

let headers = NotifyHeaders {
    timestamp: "1620000000".into(),         // Wechatpay-Timestamp
    nonce: "random_nonce_str".into(),       // Wechatpay-Nonce
    signature: "base64_signature".into(),   // Wechatpay-Signature
    serial: "platform_cert_serial".into(),  // Wechatpay-Serial
};

// 解析交易通知
let tx = client.parse_transaction_notify(&headers, &body).await?;
// tx: TransactionNotify { appid, mchid, out_trade_no, transaction_id, trade_state, ... }

// 解析退款通知
let refund = client.parse_refund_notify(&headers, &body).await?;
// refund: RefundNotify { mchid, out_trade_no, out_refund_no, refund_status, ... }
```

通知处理流程：验签 -> 时间戳新鲜度检查（±5 分钟） -> AES-256-GCM 解密 -> JSON 反序列化。

## 错误处理

所有公开方法返回 `Result<T, WxPayError>`。`WxPayError` 定义如下：

| 变体 | 说明 |
|------|------|
| `Http(reqwest::Error)` | HTTP 请求失败 |
| `Api { code, message, detail }` | 微信支付 API 返回的业务错误 |
| `SignError(String)` | 签名失败 |
| `VerifyError(String)` | 验签失败 |
| `DecryptError(String)` | 解密失败 |
| `InvalidKey(String)` | 密钥格式错误 |
| `CertError(String)` | 证书相关错误 |
| `Serialize(serde_json::Error)` | JSON 序列化/反序列化错误 |
| `Config(String)` | 配置错误 |
| `NotifyError(String)` | 通知处理错误 |

```rust
match client.jsapi_prepay(&req).await {
    Ok(resp) => println!("prepay_id: {}", resp.prepay_id),
    Err(rswxpay::WxPayError::Api { code, message, .. }) => {
        eprintln!("API error: {} - {}", code, message);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## 模块结构

```
src/
├── lib.rs              公开导出（WxPayClient, ClientConfig, WxPayError）
├── client.rs           WxPayClient — 签名 HTTP 请求 + 响应验签
├── config.rs           ClientConfig + Builder 模式
├── error.rs            WxPayError 错误枚举
├── notify.rs           回调通知验签与解密
├── crypto/
│   ├── sign.rs         请求签名（SHA256withRSA + PKCS1v15）
│   ├── verify.rs       响应验签（RSA 公钥验证）
│   └── decrypt.rs      AES-256-GCM 解密（通知/证书）
├── cert/
│   ├── store.rs        平台证书内存缓存（HashMap + RwLock）
│   └── manager.rs      证书自动下载与 12 小时刷新
├── api/
│   ├── prepay.rs       下单（JSAPI / Native / H5 / App）
│   ├── order.rs        订单查询 / 关闭
│   ├── refund.rs       退款申请 / 查询
│   └── bill.rs         账单下载
└── model/
    ├── common.rs       公共类型（Amount, Payer, SceneInfo 等）
    ├── prepay.rs       下单请求/响应 + 调起支付参数
    ├── order.rs        订单查询响应
    ├── refund.rs       退款请求/响应
    ├── bill.rs         账单请求/响应
    ├── notify.rs       通知信封 + 解密后数据类型
    └── cert.rs         证书接口响应
```

## 安全设计

- **纯 Rust 加密** — 不依赖 OpenSSL，使用 `rsa`、`aes-gcm`、`x509-cert` 纯 Rust 实现
- **强制响应验签** — fail-closed 策略，证书存储非空时缺少签名头即报错
- **通知验签** — 验签 + 时间戳新鲜度检查（±5 分钟窗口），防重放攻击
- **AES-GCM AAD** — 解密使用附加认证数据，防篡改
- **内存安全清零** — `ClientConfig` 销毁时自动清零 `api_v3_key` 和 `private_key_pem`
- **密钥校验** — `api_v3_key` 强制 32 字节 ASCII 校验
- **URL 编码** — 路径参数全部 percent-encoding，防注入
- **非阻塞签名** — RSA 签名使用 `spawn_blocking`，避免阻塞 tokio 异步运行时

## 构建与测试

```bash
cargo build           # 构建
cargo clippy          # Lint 检查
cargo test            # 运行全部 53 个单元测试
cargo test test_name  # 运行单个测试
```

## License

MIT
