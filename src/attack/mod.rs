mod attack_trait;

pub mod rsa;
pub mod diffie_hellman;

pub use attack_trait::{EncryptionAttackFactory, KeyExchangeAttackFactory};
pub use rsa::{BruteForceFactorizationAttack, SmallExponentAttack};
