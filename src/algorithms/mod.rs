mod algorithms_traits;
mod registry;

mod rsa_toy;
mod diffie_hellman;
mod elgamal;

pub use algorithms_traits::{EncryptionAlgorithm, KeyExchangeAlgorithm, AlgorithmFactory, rsa_factory, dh_factory, elgamal_factory, EncryptionPublicData, KeyExchangePublicData, EncryptionAlgorithmKind, Message, Ciphertext};
pub use registry::AlgorithmType;

pub use rsa_toy::RsaToy;
pub use diffie_hellman::DiffieHellmanToy;
pub use elgamal::ElGamalToy;
