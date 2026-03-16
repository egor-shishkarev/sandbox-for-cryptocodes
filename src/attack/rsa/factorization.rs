use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{ToPrimitive, Zero};
use crate::{algorithms::{EncryptionPublicData}, attack::attack_trait::EncryptionAttack, attack_report::{AttackReport, AttackResult}, utils::modinv};
pub struct BruteForceFactorizationAttack {} // Потом можно добавить ограничения, типы и т.д.

#[derive(PartialEq)]
enum AttackError {
    Cancelled { iterations: usize },
    TooBigModulus,
}

impl EncryptionAttack for BruteForceFactorizationAttack {
    fn name(&self) -> String {
        "Атака факторизацией (brute force)".to_string()
    }

    // fn iterations_explain(&self) -> &'static str {
    //     "Количество повторов цикла в которых мы раскладываем modulus на множители"
    // }

    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: EncryptionPublicData) -> AttackReport {
        let (public_exponent, modulus, ciphertext) = match public_data {
            EncryptionPublicData::Rsa { public_exponent, modulus, ciphertext } => (public_exponent, modulus, ciphertext),
            _ => {
                return AttackReport {
                    attack_name: Self::name(&self),
                    duration: Duration::ZERO,
                    iterations: 0,
                    result: AttackResult::Failed { reason: String::from("Атака применима только к RSA") },
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
                    "public_exponent": public_exponent.to_string(),
                    "modulus": modulus.to_string(),
                })
            }
        };

        let (p, q, iterations) = match Self::factorize(cancel, modulus.clone()) {
            Ok(v) => v,
            Err(e) => {
                match e {
                    AttackError::Cancelled { iterations } => return make_report(iterations as u64, AttackResult::Cancelled),
                    AttackError::TooBigModulus => return make_report(0, AttackResult::Failed { reason: String::from("Слишком большое значение для перебора") }),
                }
            },
        };
        let phi = (p - 1) * (q - 1);
        let d = modinv(&public_exponent.to_bigint().unwrap(), &BigInt::from(phi)).unwrap();

        let decoded_message = Self::decode(d.to_biguint().unwrap(), modulus.clone(), &ciphertext.unwrap());
        make_report(iterations as u64, AttackResult::Success { message: decoded_message })
    }
}

impl BruteForceFactorizationAttack {
    pub fn new() -> BruteForceFactorizationAttack{
        BruteForceFactorizationAttack {}
    }

    fn factorize(cancel: Arc<AtomicBool>, modulus: BigUint) -> Result<(usize, usize, usize), AttackError> {
        let end_range: usize = match modulus.sqrt().to_usize() {
            Some(v) => v,
            None => {
                return Err(AttackError::TooBigModulus);
            },
        };

        let mut first_prime: usize = 0;
        let mut second_prime: usize = 0;
        let mut iterations: usize = 0;

        for i in (3..=end_range).step_by(2) {
            iterations += 1;
            if (iterations % 10000) == 0 {
                if cancel.load(Ordering::Relaxed) {
                    return Err(AttackError::Cancelled { iterations });
                }
            }
            if &modulus % i == BigUint::zero() {
                first_prime = i;
                second_prime = (&modulus / i).to_usize().unwrap();
            }
        }

        Ok((first_prime, second_prime, iterations))
    }  

    //? По идее ничего страшного в том, что метод встречается в двух местах нет с точки зрения предметной области.
    // Так как мы не можем использовать decode функцию из RsaToy, она нам недоступна
    fn decode(private_exponent: BigUint, modulus: BigUint, bytes: &Vec<Vec<u8>>) -> String {
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in bytes {
            let number =  BigUint::from_bytes_be(&value);
            let decoded_value = number.modpow(&private_exponent, &modulus);

            let block = decoded_value.to_bytes_be();
            decoded_values.extend(block);
        }

        String::from_utf8(decoded_values).unwrap()
    }
}