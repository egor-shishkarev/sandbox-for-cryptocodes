use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}, time::{Duration, Instant}};

use num_bigint::{BigUint, ToBigInt};
use num_traits::{One, ToPrimitive, Zero};

use crate::{algorithms::EncryptionPublicData, attack::attack_trait::EncryptionAttack, attack_report::{AttackReport, AttackResult}, utils::modinv};

pub struct PohligHellmanAttack {}

enum AttackError {
    Cancelled { iterations: usize },
    TooBigModulus,
}

impl EncryptionAttack for PohligHellmanAttack {
    fn name(&self) -> String {
        "Pohlig-Hellman".to_string()
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
                    public_parameters: serde_json::json!({}),
                }
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

        let (secret_key, iterations) =
            match Self::find_secret_key(&cancel, &modulus, &generator, &key) {
                Ok(v) => v,
                Err(AttackError::Cancelled { iterations }) => {
                    return make_report(
                        iterations as u64,
                        AttackResult::Cancelled,
                    );
                }
                Err(AttackError::TooBigModulus) => {
                    return make_report(
                        0,
                        AttackResult::Failed {
                            reason: String::from("Слишком большое значение модуля"),
                        },
                    );
                }
            };

        let decoded_message = Self::decode(ciphertext, &secret_key, &modulus);
        make_report(iterations, AttackResult::Success { message: decoded_message })
    }
}

impl PohligHellmanAttack {
    pub fn new() -> PohligHellmanAttack {
        PohligHellmanAttack {}
    }

    fn tick(cancel: &Arc<AtomicBool>, iterations: &mut u64) -> Result<(), AttackError> {
        *iterations += 1;

        if (*iterations % 10_000) == 0 {
            if cancel.load(Ordering::Relaxed) {
                return Err(AttackError::Cancelled {
                    iterations: *iterations as usize,
                });
            }
        }

        Ok(())
    }

    fn decode(ciphertext: (BigUint, BigUint), secret_key: &BigUint, modulus: &BigUint) -> String {
        let s = ciphertext.0.modpow(secret_key, modulus);
        let s_inv = modinv(&s.to_bigint().unwrap(), &modulus.to_bigint().unwrap()).unwrap();

        let message = (ciphertext.1 * s_inv.to_biguint().unwrap()) % modulus;
        message.to_string()
    }

    fn find_secret_key(
        cancel: &Arc<AtomicBool>,
        modulus: &BigUint,
        generator: &BigUint,
        key: &BigUint,
    ) -> Result<(BigUint, u64), AttackError> {
        let mut iterations: u64 = 0;

        let p_minus_1 = modulus - BigUint::one();
        let factors_p_minus_1 =
            Self::factorize_prime_powers(cancel, &p_minus_1, &mut iterations)?;

        let order = Self::multiplicative_order(
            cancel,
            generator,
            modulus,
            &factors_p_minus_1,
            &mut iterations,
        )?;

        let factors_order = Self::factorize_prime_powers(cancel, &order, &mut iterations)?;

        let mut congruences = Vec::new();

        for (q, e) in factors_order {
            Self::tick(cancel, &mut iterations)?;

            let residue = Self::solve_prime_power_residue(
                cancel,
                modulus,
                generator,
                key,
                &order,
                &q,
                e,
                &mut iterations,
            )?;

            let modulus_qe = Self::biguint_pow(&q, e);
            congruences.push((residue, modulus_qe));
        }

        let secret_key = Self::crt(&congruences).ok_or(AttackError::TooBigModulus)?;
        Ok((secret_key, iterations))
    }

    fn crt(congruences: &[(BigUint, BigUint)]) -> Option<BigUint> {
        if congruences.is_empty() {
            return None;
        }
        let total_modulus = congruences
            .iter()
            .fold(BigUint::one(), |acc, (_, modulus)| acc * modulus);
        let mut result = BigUint::zero();
        for (remainder, modulus) in congruences {
            let partial_modulus = &total_modulus / modulus;
            let inverse = modinv(
                &(partial_modulus.clone() % modulus).to_bigint().unwrap(),
                &modulus.to_bigint().unwrap(),
            )?;

            result += remainder * &partial_modulus * inverse.to_biguint().unwrap();
        }

        Some(result % total_modulus)
    }

    fn factorize_prime_powers(
        cancel: &Arc<AtomicBool>,
        n: &BigUint,
        iterations: &mut u64,
    ) -> Result<Vec<(BigUint, u32)>, AttackError> {
        let zero = BigUint::zero();
        let one = BigUint::one();
        let two = BigUint::from(2u32);
    
        let mut value = n.clone();
        let mut factors: Vec<(BigUint, u32)> = Vec::new();
    
        let mut exponent_two = 0u32;
        while (&value % &two) == zero {
            Self::tick(cancel, iterations)?;
            value /= &two;
            exponent_two += 1;
        }
        
        if exponent_two > 0 {
            factors.push((two.clone(), exponent_two));
        }

        let mut divisor = BigUint::from(3u32);
        while &divisor * &divisor <= value {
            Self::tick(cancel, iterations)?;

            let mut exponent = 0u32;

            while (&value % &divisor) == zero {
                Self::tick(cancel, iterations)?;
                value /= &divisor;
                exponent += 1;
            }

            if exponent > 0 {
                factors.push((divisor.clone(), exponent));
            }

            divisor += &two;
        }

        if value > one {
            factors.push((value, 1));
        }

        Ok(factors)
    }

    fn biguint_pow(base: &BigUint, exp: u32) -> BigUint {
        let mut result = BigUint::one();

        for _ in 0..exp {
            result *= base;
        }

        result
    }

    fn small_dlog_bruteforce(
        cancel: &Arc<AtomicBool>,
        base: &BigUint,
        target: &BigUint,
        modulus: &BigUint,
        q: &BigUint,
        iterations: &mut u64,
    ) -> Result<Option<BigUint>, AttackError> {
        let limit = q.to_u64().ok_or(AttackError::TooBigModulus)?;
        let mut current = BigUint::one();

        for value in 0..limit {
            Self::tick(cancel, iterations)?;

            if &current == target {
                return Ok(Some(BigUint::from(value)));
            }

            current = (current * base) % modulus;
        }

        Ok(None)
    }

    fn solve_prime_power_residue(
        cancel: &Arc<AtomicBool>,
        p: &BigUint,
        g: &BigUint,
        y: &BigUint,
        order: &BigUint,
        q: &BigUint,
        e: u32,
        iterations: &mut u64,
    ) -> Result<BigUint, AttackError> {
        let gamma = g.modpow(&(order.clone() / q), p);

        let mut x_partial = BigUint::zero();

        for i in 0..e {
            Self::tick(cancel, iterations)?;

            let q_pow_i = Self::biguint_pow(q, i);
            let q_pow_i_plus_1 = Self::biguint_pow(q, i + 1);

            let g_to_x_partial = g.modpow(&x_partial, p);
            let g_to_x_partial_inv =
                modinv(&g_to_x_partial.to_bigint().unwrap(), &p.to_bigint().unwrap())
                    .ok_or(AttackError::TooBigModulus)?;

            let adjusted = (y * g_to_x_partial_inv.to_biguint().unwrap()) % p;

            let exponent = order.clone() / q_pow_i_plus_1;
            let h = adjusted.modpow(&exponent, p);

            let a_i = Self::small_dlog_bruteforce(
                cancel,
                &gamma,
                &h,
                p,
                q,
                iterations,
            )?
            .ok_or(AttackError::TooBigModulus)?;

            x_partial += a_i * q_pow_i;
        }

        Ok(x_partial)
    }

    fn multiplicative_order(
        cancel: &Arc<AtomicBool>,
        g: &BigUint,
        p: &BigUint,
        factors_of_p_minus_1: &[(BigUint, u32)],
        iterations: &mut u64,
    ) -> Result<BigUint, AttackError> {
        let mut order = p - BigUint::one();

        for (prime, exponent) in factors_of_p_minus_1 {
            for _ in 0..*exponent {
                Self::tick(cancel, iterations)?;

                let candidate = &order / prime;
                if g.modpow(&candidate, p) == BigUint::one() {
                    order = candidate;
                } else {
                    break;
                }
            }
        }
        Ok(order)
    }
}