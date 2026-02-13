use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use num_bigint::{BigUint, ToBigInt};
use num_traits::{One};
use crate::{attack_report::{AttackReport, AttackResult}, utils::modinv, attack::attack_trait::Attack};
pub struct FermatFactorizationAttack {} // Потом можно добавить ограничения, типы и т.д.

enum AttackError {
    Cancelled { iterations: usize },
}

impl Attack for FermatFactorizationAttack {
    fn name(&self) -> String {
        "Атака факторизацией (Ферма)".to_string()
    }

    // fn iterations_explain(&self) -> &'static str {
    //     "Количество повторов цикла в которых мы раскладываем modulus на множители"
    // }

    // TODO - сюда нужно передавать Oracle, чтобы было нагляднее, что между шифрованием и атакой есть только конкретно эти значения.
    // Короче обеспечить обособленность друг от друга
    fn run(&self, cancel: Arc<AtomicBool>, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>, seed: u64) -> AttackReport {
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
                }
            }
        };
        let phi: BigUint = (p - BigUint::one()) * (q - BigUint::one());
        let d = modinv(&public_exponent.to_bigint().unwrap(), &phi.to_bigint().unwrap()).unwrap();

        let decoded_message = Self::decode(d.to_biguint().unwrap(), modulus.clone(), ciphertext);
        make_report(iterations as u64, AttackResult::Success { message: decoded_message })
    }
}

impl FermatFactorizationAttack {
    pub fn new() -> FermatFactorizationAttack{
        FermatFactorizationAttack {}
    }

    fn factorize(cancel: Arc<AtomicBool>, modulus: BigUint) -> Result<(BigUint, BigUint, usize), AttackError> {
        let mut iterations: usize = 0;
        let mut a = modulus.sqrt();

        if &a * &a < modulus {
            a += BigUint::one();
        }

        loop {
            iterations += 1;
            if (iterations % 10000) == 0 {
                if cancel.load(Ordering::Relaxed) {
                    return Err(AttackError::Cancelled { iterations });
                }
            }
            let b_square = &a * &a - &modulus;
            if let Some(b) = Self::is_perfect_square(&b_square) {
                let p = &a - &b;
                let q = &a + &b;
                return Ok((p, q, iterations));
            }

            a += BigUint::one();
        }
    }  

    fn is_perfect_square(value: &BigUint) -> Option<BigUint> {
        let root = value.sqrt();
        if &root * &root == *value {
            return Some(root)
        }
        None
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