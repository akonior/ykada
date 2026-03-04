use crate::model::AccountBalance;
use crate::YkadaResult;

pub trait BalanceFetcher {
    fn fetch_balance(&self, address: &str) -> YkadaResult<AccountBalance>;
}
