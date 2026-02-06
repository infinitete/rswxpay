use serde::{Deserialize, Serialize};

use super::common::{Amount, Detail, Payer, SceneInfo, SettleInfo};

// ---- JSAPI ----

#[derive(Debug, Clone, Serialize)]
pub struct JsapiPrepayRequest {
    pub appid: String,
    pub mchid: String,
    pub description: String,
    pub out_trade_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_expire: Option<String>,
    pub notify_url: String,
    pub amount: Amount,
    pub payer: Payer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scene_info: Option<SceneInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_info: Option<SettleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_fapiao: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JsapiPrepayResponse {
    pub prepay_id: String,
}

/// Parameters for invoking payment in JSAPI/mini-program frontend.
#[derive(Debug, Clone, Serialize)]
pub struct JsapiPayParams {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "timeStamp")]
    pub time_stamp: String,
    #[serde(rename = "nonceStr")]
    pub nonce_str: String,
    pub package: String,
    #[serde(rename = "signType")]
    pub sign_type: String,
    #[serde(rename = "paySign")]
    pub pay_sign: String,
}

// ---- Native ----

#[derive(Debug, Clone, Serialize)]
pub struct NativePrepayRequest {
    pub appid: String,
    pub mchid: String,
    pub description: String,
    pub out_trade_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_expire: Option<String>,
    pub notify_url: String,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scene_info: Option<SceneInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_info: Option<SettleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NativePrepayResponse {
    pub code_url: String,
}

// ---- H5 ----

#[derive(Debug, Clone, Serialize)]
pub struct H5PrepayRequest {
    pub appid: String,
    pub mchid: String,
    pub description: String,
    pub out_trade_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_expire: Option<String>,
    pub notify_url: String,
    pub amount: Amount,
    pub scene_info: SceneInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_info: Option<SettleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H5PrepayResponse {
    pub h5_url: String,
}

// ---- App ----

#[derive(Debug, Clone, Serialize)]
pub struct AppPrepayRequest {
    pub appid: String,
    pub mchid: String,
    pub description: String,
    pub out_trade_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_expire: Option<String>,
    pub notify_url: String,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scene_info: Option<SceneInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settle_info: Option<SettleInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppPrepayResponse {
    pub prepay_id: String,
}

/// Parameters for invoking payment in a native App.
#[derive(Debug, Clone, Serialize)]
pub struct AppPayParams {
    pub appid: String,
    pub partnerid: String,
    pub prepayid: String,
    pub package: String,
    pub noncestr: String,
    pub timestamp: String,
    pub sign: String,
}
