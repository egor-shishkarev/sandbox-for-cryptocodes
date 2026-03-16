use super::{EncryptionAlgorithm, KeyExchangeAlgorithm};

pub enum AlgorithmType {
    Encryption(Box<dyn EncryptionAlgorithm>),
    KeyExchange(Box<dyn KeyExchangeAlgorithm>),
}

impl AlgorithmType {
    pub fn name(&self) -> &'static str {
        match self {
            AlgorithmType::Encryption(a) => a.name(),
            AlgorithmType::KeyExchange(a) => a.name(),
        }
    }
}