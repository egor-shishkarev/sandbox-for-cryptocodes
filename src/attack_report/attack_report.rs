use std::time::Duration;
use serde::{Serialize, Deserialize};
use serde_json::Value;

#[derive(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct AttackReport {
    pub attack_name: String,
    pub duration: Duration,
    pub iterations: u64,
    pub result: AttackResult,
    pub seed: u64,

    pub public_parameters: Value,
}

#[derive(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub enum AttackResult {
    Success { message: String},
    Failed { reason: String },
}