use crate::error::YkadaResult;
use crate::model::{PinPolicy, Slot, TouchPolicy};
use crate::ports::{DeviceFinder, SlotPolicyReader};

pub(crate) struct SlotPolicyParams {
    pub slot: Slot,
}

pub(crate) fn read_slot_policy_use_case<F: DeviceFinder>(
    finder: &F,
    params: SlotPolicyParams,
) -> YkadaResult<(PinPolicy, TouchPolicy)> {
    finder.find_first()?.read_slot_policy(params.slot)
}
