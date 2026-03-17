use num_integer::Integer;
use num_bigint::{BigInt, BigUint};
use crate::{algorithms::algorithms_traits::{Ciphertext, CryptoError, DifficultyLevel, EncryptionAlgorithmKind, Message}, utils::{generate_two_distinct_primes, modinv}};

use super::{algorithms_traits::EncryptionAlgorithm, EncryptionPublicData};

pub struct RsaToy {
    private_exponent: BigUint,
    pub public_exponent: BigUint,
    pub modulus: BigUint,
}

impl EncryptionAlgorithm for RsaToy {
    fn kind(&self) -> EncryptionAlgorithmKind {
        EncryptionAlgorithmKind::Rsa
    }

    // TODO - возвращаемое значение сделать просто Vec<u8> и переделать алгоритм под вычисление количества байт на число
    fn encode(&self, message: Message) -> Result<Ciphertext, CryptoError> {
        let message = match message {
            Message::Rsa(v) => v,
            other => {
                return Err(CryptoError::UnsupportedMessageType { expected: "RSA", got: other.kind_name() });
            }
        };
        let bytes = message.as_bytes();
        let n = &self.modulus;
        let e = &self.public_exponent;

        let modulus_len = n.to_bytes_be().len();
        let plain_block_len = modulus_len - 1;

        let mut encoded: Vec<BigUint> = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() {
            let chunk_size = plain_block_len.min(bytes.len() - i);
            let m = BigUint::from_bytes_be(&bytes[i..i + chunk_size]);

            debug_assert!(m < *n);

            let c = m.modpow(e, n);
            encoded.push(c);

            i += chunk_size;
        }

        Ok(Ciphertext::Rsa(Self::convert_encoded_to_bytes(encoded)))
    }

    fn decode(&self, bytes: Ciphertext) -> Result<String, CryptoError> {
        let bytes = match bytes {
            Ciphertext::Rsa(v ) => v,
            other => {
                return Err(CryptoError::UnsupportedCiphertextType {
                    expected: "RSA",
                    got: other.kind_name(),
                })
            }
        };
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in bytes {
            let number =  BigUint::from_bytes_be(&value);
            let decoded_value = number.modpow(&self.private_exponent, &self.modulus);

            let block = decoded_value.to_bytes_be();
            decoded_values.extend(block);
        }

        String::from_utf8(decoded_values).map_err(|_| CryptoError::InvalidUtf8)
    }

    fn name(&self) -> &'static str {
        "RSA"
    }

    fn print_public_parameters(&self) {
        println!("Публичные данные - ({}, {})\n", &self.public_exponent, &self.modulus);
    }

    fn get_public_data(&self, ciphertext: Option<Ciphertext>) -> EncryptionPublicData {
        let ciphertext = match ciphertext {
            Some(v) => {
                match v {
                    Ciphertext::Rsa(v) => v,
                    other => panic!("Неожиданный формат шифротекста: {}", other.kind_name()),
                }
            }
            None => Vec::new(),
            
        };
        EncryptionPublicData::Rsa { public_exponent: self.public_exponent.clone(), modulus: self.modulus.clone(), ciphertext: Some(ciphertext) }
    }
}

impl RsaToy {
    pub fn new(seed: u64, primes_length: usize) -> RsaToy {
        let (d, e, n) = Self::generate_secret_key(primes_length, seed);
        let key_len = n.to_bytes_le().len() * 8;
        debug_assert!(key_len >= 16);
    
        RsaToy {
            private_exponent: d,
            public_exponent: e,
            modulus: n,
        }
    }

    fn generate_secret_key(primes_length: usize, seed: u64) -> (BigUint, BigUint, BigUint) {
        // генерируем два простых числа p и q не равных; n = p * q.
        let (p, q) = generate_two_distinct_primes(seed, primes_length);

        let phi = (p.clone() - 1u32) * (q.clone() - 1u32);
        let _n = p * q;

        let mut open_exponent: Option<BigUint> = None;
        for candidate in [BigUint::from(3u8), BigUint::from(5u8), BigUint::from(17u8), BigUint::from(257u16)] {
            if phi.gcd(&candidate) == BigUint::from(1u8) {
                open_exponent = Some(candidate);
                break;
            }
        }
        let open_exponent = open_exponent.expect("No suitable open exponent found");

        let d = modinv(&BigInt::from(open_exponent.clone()), &BigInt::from(phi.clone()))
            .and_then(|x| x.to_biguint())
            .expect("modinv failed when generating RSA key");

        (d, open_exponent, _n)
        
    }

    pub fn bits_for_difficulty(level: DifficultyLevel) -> usize {
        match level {
            DifficultyLevel::VeryWeak => 8,
            DifficultyLevel::Weak => 16,
            DifficultyLevel::Medium => 32,
            DifficultyLevel::Strong => 64,
            DifficultyLevel::VeryStrong => 256,
        }
    }

    fn convert_encoded_to_bytes(encoded: Vec<BigUint>) -> Vec<Vec<u8>> {
        // В идеале перед зашифровкой нужно добавить первые два константных байта, потом рандом, потом 0x00, и потом само сообщение
        // Но так как это все-таки песочница, думаю этим можно пренебречь

        let mut bytes_vector: Vec<Vec<u8>> = Vec::new();

        for value in encoded {
            let sub_vector: Vec<u8> = value.to_bytes_be();
            bytes_vector.push(sub_vector);
        }

        bytes_vector
    }
}
