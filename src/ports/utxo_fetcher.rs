use crate::model::Utxo;
use crate::YkadaResult;

pub(crate) trait UtxoFetcher {
    fn fetch_utxos(&self, address: &str) -> YkadaResult<Vec<Utxo>>;
}
