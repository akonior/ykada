use crate::model::Utxo;
use crate::YkadaResult;

pub trait UtxoFetcher {
    fn fetch_utxos(&self, address: &str) -> YkadaResult<Vec<Utxo>>;
}
