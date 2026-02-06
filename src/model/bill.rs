use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TradeBillRequest {
    pub bill_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tar_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundFlowBillRequest {
    pub bill_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tar_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BillResponse {
    pub download_url: String,
    pub hash_type: String,
    pub hash_value: String,
}
