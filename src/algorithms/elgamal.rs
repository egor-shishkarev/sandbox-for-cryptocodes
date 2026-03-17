use num_bigint::{BigUint, ToBigInt};
use num_traits::{One, ToPrimitive};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use crate::{algorithms::algorithms_traits::{Ciphertext, CryptoError, DifficultyLevel, EncryptionAlgorithmKind, Message}, utils::{generate_weak_prime, generate_safe_prime, modinv, random_in_range, rng_from_seed}};

use super::{algorithms_traits::EncryptionAlgorithm, EncryptionPublicData};

pub struct ElGamalToy {
    pub modulus: BigUint, // p
    pub generator: BigUint, // g
    pub key: BigUint, // y
    secret_key: BigUint, // x
}

impl EncryptionAlgorithm for ElGamalToy {
    fn kind(&self) -> EncryptionAlgorithmKind {
        EncryptionAlgorithmKind::ElGamal
    }

    fn encode(&self, message: Message) -> Result<Ciphertext, CryptoError> {
        let (message, k) = match message {
            Message::ElGamal { message, k } => (message, k),
            other => {
                return Err(CryptoError::UnsupportedMessageType {
                    expected: "ElGamal",
                    got: other.kind_name(),
                })
            }
        };

        let c1 = self.generator.modpow(&k, &self.modulus);
        let c2 = message * self.key.modpow(&k, &self.modulus);

        Ok(Ciphertext::ElGamal { c1, c2 })
    }

    fn decode(&self, bytes: Ciphertext) -> Result<String, CryptoError> {
        let (c1, c2) = match bytes {
            Ciphertext::ElGamal { c1, c2 } => (c1, c2),
            other => {
                return Err(CryptoError::UnsupportedCiphertextType {
                    expected: "ElGamal",
                    got: other.kind_name(),
                })
            }
        };

        let s = c1.modpow(&self.secret_key, &self.modulus);
        let s_inv = match modinv(&s.to_bigint().unwrap(), &self.modulus.to_bigint().unwrap()) {
            Some(v) => v,
            None => return Err(CryptoError::InverseDoesNotExist),
        };
        let message = (c2 * s_inv.to_biguint().unwrap()) % &self.modulus;
        Ok(message.to_string())
    }

    fn name(&self) -> &'static str {
        "ElGamal"
    }

    fn print_public_parameters(&self) {
        println!("Публичные данные - ({}, {}, {})\n", &self.modulus, &self.generator, &self.key);
    }

    fn get_public_data(&self, ciphertext: Option<Ciphertext>) -> EncryptionPublicData {
        let ciphertext = match ciphertext {
            Some(v) => {
                match v {
                    Ciphertext::ElGamal { c1, c2 } => Some((c1, c2)),
                    other => panic!("Неожиданный формат шифротекста: {}", other.kind_name()),
                }
            }
            None => None
            
        };

        EncryptionPublicData::ElGamal { modulus: self.modulus.clone(), generator: self.generator.clone(), key: self.key.clone(), ciphertext: ciphertext }
    }
}

impl ElGamalToy {
    pub fn new(seed: u64, primes_length: usize) -> ElGamalToy {
        let mut rng = rng_from_seed(seed);
        let (modulus, generator) = Self::generate_params(&mut rng, primes_length);

        let secret_key = random_in_range(&mut rng, &(modulus.clone() - BigUint::from(2u8)));
        // y = g^x mod p
        let key = generator.modpow(&secret_key, &modulus);
    
        ElGamalToy {
            modulus,
            generator,
            key,
            secret_key,
        }
    }

    fn generate_prime(rng: &mut ChaCha20Rng, prime_length: usize) -> (BigUint, BigUint) {
        // Иногда будет генерировать заведомо плохое простое число, чтобы на него можно было применить атаку Pohlig-Hellman
        let is_weak_prime = rng.gen_bool(0.3);

        if is_weak_prime {
            return generate_weak_prime(rng, prime_length);
        } else {
            return generate_safe_prime(rng, prime_length)
        }
    }

    fn generate_params(rng: &mut ChaCha20Rng, prime_length: usize) -> (BigUint, BigUint) {
        let (modulus, q) = Self::generate_prime(rng, prime_length);
        let generator = match Self::get_generator(&modulus, &q) {
            Some(v) => BigUint::from(v),
            None => panic!("Не удалось получить генератор для алгоритма ElGamal"),
        };

        (modulus, generator)
    }

    fn get_generator(modulus: &BigUint, q: &BigUint) -> Option<usize> {
        let end_range = match (modulus - BigUint::from(2u8)).to_usize() {
            Some(v) => v,
            None => usize::MAX,
        };

        for candidate in 2..end_range {
            if Self::is_good_generator(&BigUint::from(candidate), &modulus, &q) {
                return Some(candidate);
            }
        }
        None
    }

    fn is_good_generator(g: &BigUint, p: &BigUint, q: &BigUint) -> bool {
        g.modpow(&BigUint::from(2u32), p) != BigUint::one()
            && g.modpow(q, p) != BigUint::one()
    }

    pub fn bits_for_difficulty(level: DifficultyLevel) -> usize {
        match level {
            DifficultyLevel::VeryWeak => 8,
            DifficultyLevel::Weak => 16,
            DifficultyLevel::Medium => 24,
            DifficultyLevel::Strong => 64,
            DifficultyLevel::VeryStrong => 256,
        }
    }
}
