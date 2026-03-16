use std::{iter, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

use num_bigint::{BigUint, ToBigInt};
use num_traits::{ToPrimitive, Zero};

use crate::{algorithms::EncryptionPublicData, attack::attack_trait::EncryptionAttack, attack_report::{AttackReport, AttackResult}, utils::modinv};

pub struct BruteForceElGamalAttack {}

enum AttackError {
    Cancelled { iterations: usize },
    TooBigModulus,
}

impl EncryptionAttack for BruteForceElGamalAttack {
    fn name(&self) -> String {
        "Атака перебором (brute force)".to_string()
    }

    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: EncryptionPublicData) -> AttackReport {
        let (modulus, generator, key, ciphertext) = match public_data {
            EncryptionPublicData::ElGamal { modulus, generator, key, ciphertext } => (modulus, generator, key, ciphertext),
            _ => {
                return AttackReport {
                    attack_name: Self::name(&self),
                    duration: Duration::ZERO,
                    iterations: 0,
                    result: AttackResult::Failed { reason: String::from("Атака применима только к ElGamal") },
                    seed,
                    public_parameters: serde_json::json!({}) }
            }
        };

        let start = Instant::now();

        let make_report = |iterations: u64, result: AttackResult| {
            AttackReport {
                attack_name: Self::name(&self),
                duration: start.elapsed(),
                iterations,
                result,
                seed,
                public_parameters: serde_json::json!({
                    "modulus": modulus.to_string(),
                    "generator": generator.to_string(),
                    "key": key.to_string(),
                })
            }
        };

        let (secret_key, iterations) = match Self::find_seceret_key(cancel, &modulus, &generator, &key) {
            Ok(v) => v,
            Err(err) => {
                match err {
                    AttackError::Cancelled { iterations } => return make_report(iterations as u64, AttackResult::Cancelled),
                    AttackError::TooBigModulus => return make_report(0, AttackResult::Failed { reason: String::from("Слишком большой модуль для перебора") }),
                }
            }
        };

        let decoded_message = Self::decode(ciphertext, &secret_key, &modulus);
        make_report(iterations as u64, AttackResult::Success { message: decoded_message })
    }
}

impl BruteForceElGamalAttack {
    pub fn new() -> BruteForceElGamalAttack{
        BruteForceElGamalAttack {}
    }

    fn decode(ciphertext: (BigUint, BigUint), secret_key: &BigUint, modulus: &BigUint) -> String {
        let s = ciphertext.0.modpow(&secret_key, &modulus);
        let s_inv = modinv(&s.to_bigint().unwrap(), &modulus.to_bigint().unwrap()).unwrap();

        let message = (ciphertext.1 * s_inv.to_biguint().unwrap()) % modulus;
        message.to_string()
    }  

    fn find_seceret_key(cancel: Arc<AtomicBool>, modulus: &BigUint, generator: &BigUint, key: &BigUint) -> Result<(BigUint, usize), AttackError> {
        // Если modulus маленький, то можно перебрать все значения и найти x - секретный ключ
        // Также, если k был маленьким, то его тоже можно перебрать. Но k уже не является публичной частью, так что тут спорно

        let end_range: usize = match modulus.to_usize() {
            Some(v) => v,
            None => {
                return Err(AttackError::TooBigModulus);
            },
        };

        let mut iterations: usize = 0;
        let mut secret_key: BigUint = BigUint::zero();

        for i in 1..end_range {
            iterations += 1;
            if (iterations % 10000) == 0 {
                if cancel.load(Ordering::Relaxed) {
                    return Err(AttackError::Cancelled { iterations });
                }
            }

            if generator.modpow(&BigUint::from(i), &modulus) == *key {
                // Нашли секретный ключ - i
                secret_key = BigUint::from(i);
                break;
                
            }
        }

        Ok((secret_key, iterations))
    }
}