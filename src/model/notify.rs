use serde::Deserialize;

use super::common::Payer;
use super::order::OrderAmount;

/// Raw notification envelope from WeChat Pay callback POST body.
#[derive(Debug, Clone, Deserialize)]
pub struct NotifyEnvelope {
    pub id: String,
    pub create_time: String,
    pub event_type: String,
    pub resource_type: String,
    pub resource: NotifyResource,
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyResource {
    pub algorithm: String,
    pub ciphertext: String,
    pub nonce: String,
    #[serde(default)]
    pub associated_data: String,
    #[serde(default)]
    pub original_type: Option<String>,
}

/// Headers extracted from a WeChat Pay notification request.
#[derive(Debug, Clone)]
pub struct NotifyHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub serial: String,
}

/// Decrypted transaction notification.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionNotify {
    pub appid: String,
    pub mchid: String,
    pub out_trade_no: String,
    pub transaction_id: String,
    pub trade_type: String,
    pub trade_state: String,
    pub trade_state_desc: String,
    pub bank_type: String,
    pub success_time: String,
    pub payer: Payer,
    pub amount: OrderAmount,
    #[serde(default)]
    pub attach: Option<String>,
}

/// Decrypted refund notification.
#[derive(Debug, Clone, Deserialize)]
pub struct RefundNotify {
    pub mchid: String,
    pub out_trade_no: String,
    pub transaction_id: String,
    pub out_refund_no: String,
    pub refund_id: String,
    pub refund_status: String,
    #[serde(default)]
    pub success_time: Option<String>,
    pub user_received_account: String,
    pub amount: RefundNotifyAmount,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundNotifyAmount {
    pub total: i64,
    pub refund: i64,
    pub payer_total: i64,
    pub payer_refund: i64,
}
