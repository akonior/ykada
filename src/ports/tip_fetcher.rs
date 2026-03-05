use crate::YkadaResult;

pub(crate) trait TipFetcher {
    fn fetch_tip_slot(&self) -> YkadaResult<u64>;
}
