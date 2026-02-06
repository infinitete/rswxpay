use crate::client::{WxPayClient, encode_path_segment};
use crate::error::WxPayError;
use crate::model::refund::{RefundRequest, RefundResponse};

impl WxPayClient {
    /// Create a refund.
    ///
    /// POST /v3/pay/refund/domestic/refunds
    pub async fn create_refund(&self, req: &RefundRequest) -> Result<RefundResponse, WxPayError> {
        self.post("/v3/pay/refund/domestic/refunds", req).await
    }

    /// Query refund by out_refund_no.
    ///
    /// GET /v3/pay/refund/domestic/refunds/{out_refund_no}
    pub async fn query_refund(&self, out_refund_no: &str) -> Result<RefundResponse, WxPayError> {
        let path = format!(
            "/v3/pay/refund/domestic/refunds/{}",
            encode_path_segment(out_refund_no)
        );
        self.get(&path).await
    }
}
