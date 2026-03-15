use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, ToPrimitive, Zero};
use rand_chacha::ChaCha20Rng;
use crate::{algorithms::algorithms_traits::{Ciphertext, EncryptionAlgorithmKind, Message}, utils::{generate_safe_prime, modinv, random_in_range, rng_from_seed}};

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

    fn encode(&self, message: Message) -> Ciphertext {
        let (message, k) = match message {
            Message::ElGamal{message, k} => (message, k),
            Message::Rsa(_) => {
                println!("Неподдерживаемый тип сообщения");
                (BigUint::zero(), BigUint::zero())
            }
        };

        let c1 = self.generator.modpow(&k, &self.modulus);
        let c2 = message * self.key.modpow(&k, &self.modulus);

        Ciphertext::ElGamal { c1, c2 }
    }

    fn decode(&self, bytes: Ciphertext) -> String {
        let (c1, c2) = match bytes {
            Ciphertext::ElGamal{c1 , c2} => (c1, c2),
            Ciphertext::Rsa(_) => {
                println!("Неподдерживаемый тип шифротекста");
                (BigUint::zero(), BigUint::zero())
            },
        };

        let s = c1.modpow(&self.secret_key, &self.modulus);
        let s_inv = match modinv(&s.to_bigint().unwrap(), &self.modulus.to_bigint().unwrap()) {
            Some(v) => v,
            None => {
                println!("Не удалось получить s^-1");
                BigInt::zero()
            }
        };
        let message = (c2 * s_inv.to_biguint().unwrap()) % &self.modulus;
        message.to_string()
    }

    fn name(&self) -> &'static str {
        "El Gamal"
    }

    fn print_public_parameters(&self) {
        println!("\nДлина ключа (модуля) в битах - {}", &self.modulus.to_bytes_be().len() * 8);
        println!("Публичные данные - ({}, {}, {})\n", &self.modulus, &self.generator, &self.key);
    }

    fn get_public_data(&self, ciphertext: Option<Ciphertext>) -> EncryptionPublicData {
        let (c1, c2) = match ciphertext {
            Some(v) => {
                match v {
                    Ciphertext::ElGamal { c1, c2 } => (c1, c2),
                    Ciphertext::Rsa(_) => {
                        println!("Неподдерживаемый тип шифротекста");
                        (BigUint::zero(), BigUint::zero())
                    }
                }
            }
            None => {
                println!("Отсутствует шифротекст");
                (BigUint::zero(), BigUint::zero())
            }
            
        };

        EncryptionPublicData::ElGamal { modulus: self.modulus.clone(), generator: self.generator.clone(), key: self.key.clone(), ciphertext: (c1, c2) }
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

    fn generate_params(rng: &mut ChaCha20Rng, prime_length: usize) -> (BigUint, BigUint) {
        let (modulus, q) = generate_safe_prime(rng, prime_length);
        let generator = match Self::get_generator(&modulus, &q) {
            Some(v) => BigUint::from(v),
            None => BigUint::zero(), // TODO - ну не ноль конечно же, но хз пока что сюда проставить
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
}
