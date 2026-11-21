use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};

pub(crate) trait SlotPolicyReader {
    fn read_slot_policy(&mut self, slot: Slot) -> YkadaResult<(PinPolicy, TouchPolicy)>;
}
