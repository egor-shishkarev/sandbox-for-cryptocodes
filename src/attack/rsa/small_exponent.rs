use std::{time::Instant};
use num_bigint::{BigUint};
use num_traits::{One, ToPrimitive, Zero};
use crate::{attack_report::{AttackReport, AttackResult}, attack::attack_trait::Attack};
pub struct SmallExponentAttack {} // Потом можно добавить ограничения, типы и т.д.

impl Attack for SmallExponentAttack {
    fn name(&self) -> String {
        "Атака для малой экспоненты".to_string()
    }

    // fn iterations_explain(&self) -> &'static str {
    //     "Количество повторов цикла в которых мы раскладываем modulus на множители"
    // }

    fn run(&self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>, seed: u64) -> AttackReport {
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

        let public_exponent_u32: u32 = match public_exponent.to_u32() {
            Some(v) => v,
            None => {
                return make_report(0, AttackResult::Failed { reason: String::from("Слишком большое значение публичной экспоненты") }); 
            }
        };

        let (decoded_vector, iterations) = match Self::try_small_exponent_attack(ciphertext, public_exponent_u32) {
            Some(v) => v,
            None => {
                return make_report(0, AttackResult::Failed { reason: String::from("Значение m^e было больше n") });
            }
        };

        let decoded_message = Self::decode(decoded_vector);
        make_report(iterations as u64, AttackResult::Success { message: decoded_message })
    }
}

impl SmallExponentAttack {
    pub fn new() -> SmallExponentAttack{
        SmallExponentAttack {}
    }

    fn decode(decoded_vector: Vec<BigUint>) -> String {
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in decoded_vector {
            let block = value.to_bytes_be();
            decoded_values.extend(block);
        }

        String::from_utf8(decoded_values).unwrap()
    }

    fn try_small_exponent_attack(ciphertext: &Vec<Vec<u8>> , public_exponent: u32) -> Option<(Vec<BigUint>, usize)> {
        let mut iterations: usize= 0;
        let mut biguint_vector: Vec<BigUint> = Vec::new();
        for bytes_vector in ciphertext {
            biguint_vector.push(BigUint::from_bytes_be(&bytes_vector));
        }

        let mut decoded_vector: Vec<BigUint> = Vec::new();
        for i in 0..biguint_vector.len() {
            iterations += 1;
            let decoded_value = Self::integer_nth_root(&biguint_vector[i], public_exponent);
            if decoded_value.pow(public_exponent) != biguint_vector[i] {
                return None
            }
            decoded_vector.push(decoded_value);
        }

        Some((decoded_vector, iterations))
    }

    fn integer_nth_root(value: &BigUint, n: u32) -> BigUint {
        if value.is_zero() {
            return BigUint::zero();
        }
        if n == 1 {
            return value.clone();
        }
    
        let mut low = BigUint::zero();
        let mut high = value.clone() + BigUint::one();
    
        while &low + BigUint::one() < high {
            let mid: BigUint = (&low + &high) >> 1;
    
            let mid_pow = mid.pow(n);
            if mid_pow <= *value {
                low = mid;
            } else {
                high = mid;
            }
        }
    
        low
    }
}
