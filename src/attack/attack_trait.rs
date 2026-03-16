use std::sync::{Arc, atomic::AtomicBool};

use crate::{algorithms::{EncryptionPublicData, KeyExchangePublicData}, attack_report::AttackReport};

pub trait EncryptionAttack: Send {
    fn name(&self) -> String;
    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: EncryptionPublicData) -> AttackReport;
}

pub trait KeyExchangeAttack: Send {
    fn name(&self) -> String;
    fn run(&self, cancel: Arc<AtomicBool>, seed:u64, public_data: KeyExchangePublicData) -> AttackReport;
}

pub trait GenericAttack<P>: Send {
    fn name(&self) -> String;
    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: P) -> AttackReport;
}

impl<T> GenericAttack<EncryptionPublicData> for T
where
    T: EncryptionAttack + Send,
{
    fn name(&self) -> String {
        EncryptionAttack::name(self)
    }

    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: EncryptionPublicData) -> AttackReport {
        EncryptionAttack::run(self, cancel, seed, public_data)
    }
}

impl<T> GenericAttack<KeyExchangePublicData> for T
where
    T: KeyExchangeAttack + Send,
{
    fn name(&self) -> String {
        KeyExchangeAttack::name(self)
    }

    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: KeyExchangePublicData) -> AttackReport {
        KeyExchangeAttack::run(self, cancel, seed, public_data)
    }
}

pub type EncryptionAttackFactory = fn() -> Box<dyn GenericAttack<EncryptionPublicData>>;
pub type KeyExchangeAttackFactory = fn() -> Box<dyn GenericAttack<KeyExchangePublicData>>;