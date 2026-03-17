use num_bigint::BigUint;

use super::AlgorithmType;

#[derive(Debug)]
pub enum CryptoError {
    UnsupportedMessageType { expected: &'static str, got: &'static str },
    UnsupportedCiphertextType { expected: &'static str, got: &'static str },
    InverseDoesNotExist,
    InvalidUtf8,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::UnsupportedMessageType { expected, got } => {
                write!(f, "Неподдерживаемый тип сообщения (ожидалось {expected}, получено {got})")
            }
            CryptoError::UnsupportedCiphertextType { expected, got } => {
                write!(f, "Неподдерживаемый тип шифротекста (ожидалось {expected}, получено {got})")
            }
            CryptoError::InverseDoesNotExist => write!(f, "Инверсия параметра не существует"),
            CryptoError::InvalidUtf8 => write!(f, "Неправильный формат для UTF-8 в расшифрованных байтах"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub trait EncryptionAlgorithm {
    fn kind(&self) -> EncryptionAlgorithmKind;
    fn encode(&self, message: Message) -> Result<Ciphertext, CryptoError>; // В идеале Bytes, но пока хз как написать правильно
    fn decode(&self, bytes: Ciphertext) -> Result<String, CryptoError>;
    fn name(&self) -> &'static str;
    fn print_public_parameters(&self);
    fn get_public_data(&self, ciphertext: Option<Ciphertext>) -> EncryptionPublicData; 
}

pub enum Ciphertext {
    Rsa(Vec<Vec<u8>>),
    ElGamal{
        c1: BigUint,
        c2: BigUint,
    },
}

impl Ciphertext {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Ciphertext::Rsa(_) => "RSA",
            Ciphertext::ElGamal { .. } => "ElGamal",
        }
    }
}

pub enum Message {
    Rsa(String),
    ElGamal {
        message: BigUint,
        k: BigUint,
    },
}

impl Message {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Message::Rsa(_) => "RSA",
            Message::ElGamal { .. } => "ElGamal",
        }
    }
}

pub enum EncryptionAlgorithmKind {
    Rsa,
    ElGamal,
}

pub trait KeyExchangeAlgorithm {
    fn establish_shared_secret(&self) -> BigUint;
    fn name(&self) -> &'static str;
    fn print_public_parameters(&self);
    fn get_public_data(&self) -> KeyExchangePublicData;
}

// trait CompressionAlgorithm
// trait ErrorCorrectionCode

pub type AlgorithmFactory = fn (u64, usize) -> AlgorithmType; 

#[derive(Clone, Copy, Debug)]
pub enum DifficultyLevel {
    VeryWeak = 1,
    Weak = 2,
    Medium = 3,
    Strong = 4,
    VeryStrong = 5,
}

impl DifficultyLevel {
    pub const MIN: usize = 1;
    pub const MAX: usize = 5;

    pub fn from_choice(choice: usize) -> DifficultyLevel {
        match choice {
            1 => DifficultyLevel::VeryWeak,
            2 => DifficultyLevel::Weak,
            3 => DifficultyLevel::Medium,
            4 => DifficultyLevel::Strong,
            5 => DifficultyLevel::VeryStrong,
            _ => DifficultyLevel::Medium,
        }
    }
}

pub fn rsa_factory(seed: u64, bits: usize) -> AlgorithmType {
    AlgorithmType::Encryption(Box::new(super::RsaToy::new(seed, bits)))
}

pub fn elgamal_factory(seed: u64, bits: usize) -> AlgorithmType {
    AlgorithmType::Encryption(Box::new(super::ElGamalToy::new(seed, bits)))
}

pub fn dh_factory(seed: u64, bits: usize) -> AlgorithmType {
    AlgorithmType::KeyExchange(Box::new(super::DiffieHellmanToy::new(seed, bits)))
}

pub enum EncryptionPublicData {
    Rsa { public_exponent: BigUint, modulus: BigUint, ciphertext: Option<Vec<Vec<u8>>> },
    ElGamal { modulus: BigUint, generator: BigUint, key: BigUint, ciphertext: Option<(BigUint, BigUint)> }
}

pub enum KeyExchangePublicData {
    DiffieHellman { modulus: BigUint, generator: BigUint, alice_public_message: BigUint, bob_public_message: BigUint },
}



