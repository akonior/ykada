use crate::YkadaResult;

pub trait TipFetcher {
    fn fetch_tip_slot(&self) -> YkadaResult<u64>;
}
