use std::sync::{Arc, atomic::AtomicBool};

use crate::{algorithms::{EncryptionPublicData, KeyExchangePublicData}, attack_report::AttackReport};

pub type EncryptionAttackFactory = fn() -> Box<dyn EncryptionAttack + Send>;
pub type KeyExchangeAttackFactory = fn() -> Box<dyn KeyExchangeAttack + Send>;

pub trait EncryptionAttack: Send {
    fn name(&self) -> String;
    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: EncryptionPublicData) -> AttackReport;
}

pub trait KeyExchangeAttack: Send {
    fn name(&self) -> String;
    fn run(&self, cancel: Arc<AtomicBool>, seed:u64, public_data: KeyExchangePublicData) -> AttackReport;
}