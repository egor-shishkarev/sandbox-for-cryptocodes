mod attack_trait;
pub mod rsa;

pub use attack_trait::{AttackFactory};
pub use rsa::{BruteForceFactorizationAttack, SmallExponentAttack};
