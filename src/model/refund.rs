use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct RefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_trade_no: Option<String>,
    pub out_refund_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_url: Option<String>,
    pub amount: RefundAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funds_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_detail: Option<Vec<RefundGoodsDetail>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundAmount {
    pub refund: i64,
    pub total: i64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<RefundFrom>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundFrom {
    pub account: String,
    pub amount: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefundGoodsDetail {
    pub merchant_goods_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wechatpay_goods_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_name: Option<String>,
    pub unit_price: i64,
    pub refund_amount: i64,
    pub refund_quantity: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundResponse {
    pub refund_id: String,
    pub out_refund_no: String,
    pub transaction_id: String,
    pub out_trade_no: String,
    pub channel: String,
    pub user_received_account: String,
    #[serde(default)]
    pub success_time: Option<String>,
    pub create_time: String,
    pub status: String,
    pub amount: RefundResponseAmount,
    #[serde(default)]
    pub funds_account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundResponseAmount {
    pub total: i64,
    pub refund: i64,
    pub payer_total: i64,
    pub payer_refund: i64,
    pub settlement_refund: i64,
    pub settlement_total: i64,
    pub discount_refund: i64,
    pub currency: String,
    #[serde(default)]
    pub from: Option<Vec<RefundFrom>>,
}
