use serde::Deserialize;

use super::common::Payer;

#[derive(Debug, Clone, Deserialize)]
pub struct OrderQueryResponse {
    pub appid: String,
    pub mchid: String,
    pub out_trade_no: String,
    #[serde(default)]
    pub transaction_id: Option<String>,
    pub trade_state: String,
    pub trade_state_desc: String,
    #[serde(default)]
    pub trade_type: Option<String>,
    #[serde(default)]
    pub bank_type: Option<String>,
    #[serde(default)]
    pub success_time: Option<String>,
    #[serde(default)]
    pub amount: Option<OrderAmount>,
    #[serde(default)]
    pub payer: Option<Payer>,
    #[serde(default)]
    pub attach: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrderAmount {
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub payer_total: Option<i64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub payer_currency: Option<String>,
}
