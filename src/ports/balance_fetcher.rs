use crate::model::AccountBalance;
use crate::YkadaResult;

pub(crate) trait BalanceFetcher {
    fn fetch_balance(&self, address: &str) -> YkadaResult<AccountBalance>;
}
