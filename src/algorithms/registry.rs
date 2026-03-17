use super::{EncryptionAlgorithm, KeyExchangeAlgorithm};

pub enum AlgorithmType {
    Encryption(Box<dyn EncryptionAlgorithm>),
    KeyExchange(Box<dyn KeyExchangeAlgorithm>),
}
