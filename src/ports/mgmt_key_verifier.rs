use crate::error::YkadaResult;
use crate::model::ManagementKey;

pub trait ManagementKeyVerifier {
    fn authenticate(&mut self, mgmt_key: Option<&ManagementKey>) -> YkadaResult<()>;
}
