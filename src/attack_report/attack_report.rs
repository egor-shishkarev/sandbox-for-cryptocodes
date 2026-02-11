use num_bigint::BigUint;
use std::time::Duration;

#[derive(Debug)]
pub struct AttackReport {
    pub attack_name: &'static str,
    pub duration: Duration,
    pub iterations: u64,
    pub result: AttackResult,
    pub seed: BigUint,
}

#[derive(Debug)]
pub enum AttackResult {
    Success { message: String},
    Failed { reason: String },
}