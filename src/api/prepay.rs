use crate::client::WxPayClient;
use crate::client::current_timestamp_str;
use crate::crypto::sign::sign_sha256_rsa;
use crate::error::WxPayError;
use crate::model::prepay::*;

impl WxPayClient {
    /// JSAPI Prepay (mini-program / official account).
    ///
    /// POST /v3/pay/transactions/jsapi
    pub async fn jsapi_prepay(
        &self,
        req: &JsapiPrepayRequest,
    ) -> Result<JsapiPrepayResponse, WxPayError> {
        self.post("/v3/pay/transactions/jsapi", req).await
    }

    /// Native Prepay (QR code).
    ///
    /// POST /v3/pay/transactions/native
    pub async fn native_prepay(
        &self,
        req: &NativePrepayRequest,
    ) -> Result<NativePrepayResponse, WxPayError> {
        self.post("/v3/pay/transactions/native", req).await
    }

    /// H5 Prepay.
    ///
    /// POST /v3/pay/transactions/h5
    pub async fn h5_prepay(&self, req: &H5PrepayRequest) -> Result<H5PrepayResponse, WxPayError> {
        self.post("/v3/pay/transactions/h5", req).await
    }

    /// App Prepay.
    ///
    /// POST /v3/pay/transactions/app
    pub async fn app_prepay(
        &self,
        req: &AppPrepayRequest,
    ) -> Result<AppPrepayResponse, WxPayError> {
        self.post("/v3/pay/transactions/app", req).await
    }

    /// Build JSAPI/mini-program payment invocation parameters from a prepay_id.
    ///
    /// The returned `JsapiPayParams` can be sent to the frontend to invoke payment.
    pub fn build_jsapi_pay_params(
        &self,
        appid: &str,
        prepay_id: &str,
    ) -> Result<JsapiPayParams, WxPayError> {
        let timestamp = current_timestamp_str();
        let nonce = uuid::Uuid::new_v4().to_string();
        let package = format!("prepay_id={prepay_id}");

        // Sign: "{appid}\n{timestamp}\n{nonce}\n{package}\n"
        let sign_msg = format!("{appid}\n{timestamp}\n{nonce}\n{package}\n");
        let pay_sign = sign_sha256_rsa(&self.signing_key, &sign_msg)?;

        Ok(JsapiPayParams {
            app_id: appid.to_string(),
            time_stamp: timestamp,
            nonce_str: nonce,
            package,
            sign_type: "RSA".to_string(),
            pay_sign,
        })
    }

    /// Build App payment invocation parameters from a prepay_id.
    ///
    /// The returned `AppPayParams` can be used by the native App SDK.
    pub fn build_app_pay_params(
        &self,
        appid: &str,
        prepay_id: &str,
    ) -> Result<AppPayParams, WxPayError> {
        let timestamp = current_timestamp_str();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Sign: "{appid}\n{timestamp}\n{nonce}\nprepay_id={prepay_id}\n"
        let sign_msg = format!("{appid}\n{timestamp}\n{nonce}\nprepay_id={prepay_id}\n");
        let sign = sign_sha256_rsa(&self.signing_key, &sign_msg)?;

        Ok(AppPayParams {
            appid: appid.to_string(),
            partnerid: self.config.mch_id.clone(),
            prepayid: prepay_id.to_string(),
            package: "Sign=WXPay".to_string(),
            noncestr: nonce,
            timestamp,
            sign,
        })
    }
}
