use crate::client::{WxPayClient, encode_path_segment};
use crate::error::WxPayError;
use crate::model::bill::*;

impl WxPayClient {
    /// Get trade bill download URL.
    ///
    /// GET /v3/bill/tradebill?bill_date=2023-01-01&bill_type=ALL
    pub async fn get_trade_bill(&self, req: &TradeBillRequest) -> Result<BillResponse, WxPayError> {
        let mut path = format!("/v3/bill/tradebill?bill_date={}", encode_path_segment(&req.bill_date));
        if let Some(ref bill_type) = req.bill_type {
            path.push_str(&format!("&bill_type={}", encode_path_segment(bill_type)));
        }
        if let Some(ref tar_type) = req.tar_type {
            path.push_str(&format!("&tar_type={}", encode_path_segment(tar_type)));
        }
        self.get(&path).await
    }

    /// Get fund flow bill download URL.
    ///
    /// GET /v3/bill/fundflowbill?bill_date=2023-01-01&account_type=BASIC
    pub async fn get_fund_flow_bill(
        &self,
        req: &FundFlowBillRequest,
    ) -> Result<BillResponse, WxPayError> {
        let mut path = format!("/v3/bill/fundflowbill?bill_date={}", encode_path_segment(&req.bill_date));
        if let Some(ref account_type) = req.account_type {
            path.push_str(&format!("&account_type={}", encode_path_segment(account_type)));
        }
        if let Some(ref tar_type) = req.tar_type {
            path.push_str(&format!("&tar_type={}", encode_path_segment(tar_type)));
        }
        self.get(&path).await
    }

    /// Download a bill file from the URL returned by `get_trade_bill` or `get_fund_flow_bill`.
    pub async fn download_bill(&self, download_url: &str) -> Result<bytes::Bytes, WxPayError> {
        self.get_bytes(download_url).await
    }
}
