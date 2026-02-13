use num_bigint::BigUint;

use super::AlgorithmType;

pub trait EncryptionAlgorithm {
    fn encode(&self, message: &str) -> Vec<Vec<u8>>; // В идеале Bytes, но пока хз как написать правильно
    fn decode(&self, bytes: Vec<Vec<u8>>) -> String;
    fn name(&self) -> &'static str;
    fn print_public_parameters(&self);
    fn get_public_data(&self) -> EncryptionPublicData; 
    // TODO - нужно еще как-то получать публичные параметры, помимо их вывода.
    // Однако как сделать так, чтобы можно было получать параметры разных типов?
    // Даже с генериками это звучит пока не понятно
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

pub fn rsa_factory(seed: u64, bits: usize) -> AlgorithmType {
    AlgorithmType::Encryption(Box::new(super::RsaToy::new(seed, bits)))
}

pub fn dh_factory(seed: u64, bits: usize) -> AlgorithmType {
    AlgorithmType::KeyExchange(Box::new(super::DiffieHellmanToy::new(seed, bits)))
}


pub enum EncryptionPublicData {
    // TODO - Все таки шифротекст доступен публично и на момент атаки мы его знаем. Просто у меня нет его в self, поэтому передаваться будет None
    Rsa { public_exponent: BigUint, modulus: BigUint, ciphertext: Option<Vec<Vec<u8>>> },
}

pub enum KeyExchangePublicData {
    DiffieHellman { modulus: BigUint, generator: BigUint, alice_public_message: BigUint, bob_public_message: BigUint },
}