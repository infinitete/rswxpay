use serde::Serialize;

use crate::client::{WxPayClient, encode_path_segment};
use crate::error::WxPayError;
use crate::model::order::OrderQueryResponse;

impl WxPayClient {
    /// Query order by merchant out_trade_no.
    ///
    /// GET /v3/pay/transactions/out-trade-no/{out_trade_no}?mchid={mchid}
    pub async fn query_order_by_out_trade_no(
        &self,
        out_trade_no: &str,
    ) -> Result<OrderQueryResponse, WxPayError> {
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}?mchid={}",
            encode_path_segment(out_trade_no),
            encode_path_segment(&self.config.mch_id)
        );
        self.get(&path).await
    }

    /// Query order by WeChat transaction_id.
    ///
    /// GET /v3/pay/transactions/id/{transaction_id}?mchid={mchid}
    pub async fn query_order_by_transaction_id(
        &self,
        transaction_id: &str,
    ) -> Result<OrderQueryResponse, WxPayError> {
        let path = format!(
            "/v3/pay/transactions/id/{}?mchid={}",
            encode_path_segment(transaction_id),
            encode_path_segment(&self.config.mch_id)
        );
        self.get(&path).await
    }

    /// Close order.
    ///
    /// POST /v3/pay/transactions/out-trade-no/{out_trade_no}/close
    /// Returns `()` on success (HTTP 204).
    pub async fn close_order(&self, out_trade_no: &str) -> Result<(), WxPayError> {
        let path = format!(
            "/v3/pay/transactions/out-trade-no/{}/close",
            encode_path_segment(out_trade_no)
        );

        #[derive(Serialize)]
        struct CloseBody {
            mchid: String,
        }

        self.post_no_content(
            &path,
            &CloseBody {
                mchid: self.config.mch_id.clone(),
            },
        )
        .await
    }
}
