use num_integer::Integer;
use num_bigint::{BigInt, BigUint};
use num_traits::{Zero};

use crate::utils::modinv;

use super::cryptocode::Algorithm;

pub struct RsaToy {
    private_exponent: BigUint,
    pub public_exponent: BigUint,
    pub modulus: BigUint,
}

// Можно еще сделать создание алгоритма с нужными параметрами, допустим длина секретов и т.д.
impl Algorithm for RsaToy {
    fn encode(&self, message: &str) -> Vec<Vec<u8>> {
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

        Self::convert_encoded_to_bytes(encoded)
    }

    fn decode(&self, bytes: Vec<Vec<u8>>) -> String {
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in bytes {
            let number =  BigUint::from_bytes_be(&value);
            let decoded_value = number.modpow(&self.private_exponent, &self.modulus);

            let block = decoded_value.to_bytes_be();
            decoded_values.extend(block);
        }

        String::from_utf8(decoded_values).unwrap()
    }

    fn name() -> &'static str {
        "RSA"
    }

    fn print_public_parameters(&self) {
        println!("Длина ключа (модуля) в битах - {}", &self.modulus.to_bytes_be().len() * 8);
        println!("Публичные данные - ({}, {})", &self.public_exponent, &self.modulus);
    }
}

impl RsaToy {
    pub fn new(primes_length: usize, _seed: BigUint) -> RsaToy {
        let (d, e, n) = Self::generate_secret_key(primes_length, BigUint::zero());
        let key_len = n.to_bytes_le().len() * 8;
        debug_assert!(key_len >= 16);
    
        RsaToy {
            private_exponent: d,
            public_exponent: e,
            modulus: n,
        }
    }

    fn generate_secret_key(primes_length: usize, _seed: BigUint) -> (BigUint, BigUint, BigUint) {
        // генерируем два простых числа p и q не равных; n = p * q.
        let p_bits = num_primes::Generator::new_prime(primes_length).to_bytes_be(); // TODO - seed
        let q_bits = num_primes::Generator::new_prime(primes_length).to_bytes_be(); // TODO - seed
        let p = BigUint::from_bytes_be(&p_bits);
        let q = BigUint::from_bytes_be(&q_bits);

        let phi = (p.clone() - 1u32) * (q.clone() - 1u32);
        let _n = p * q;

        let mut open_exponent: Option<BigUint> = None;
        for candidate in [BigUint::from(3u8), BigUint::from(5u8), BigUint::from(17u8), BigUint::from(257u16)] { // TODO - лучше сделать
            if phi.gcd(&candidate) == BigUint::from(1u8) {
                open_exponent = Some(candidate);
                break;
            }
        }
        let open_exponent = open_exponent.expect("No suitable open exponent found");

        let d = modinv(&BigInt::from(open_exponent.clone()), &BigInt::from(phi.clone()))
            .and_then(|x| x.to_biguint())
            .expect("modinv failed");

        (d, open_exponent, _n)
        
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
