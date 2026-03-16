mod attack_trait;

pub mod rsa;
pub mod diffie_hellman;
pub mod elgamal;

pub use attack_trait::{EncryptionAttackFactory, KeyExchangeAttackFactory};
pub use rsa::{BruteForceFactorizationAttack, SmallExponentAttack};
pub use diffie_hellman::{BSGSAttack, BruteForceDiffieHellmanAttack};
pub use elgamal::{BruteForceElGamalAttack};
