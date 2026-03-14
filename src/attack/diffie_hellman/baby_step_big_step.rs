use std::{collections::HashMap, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use num_bigint::{BigUint, ToBigInt};
use num_traits::{ToPrimitive, One};
use crate::{algorithms::{KeyExchangePublicData}, attack::attack_trait::{KeyExchangeAttack}, attack_report::{AttackReport, AttackResult}, utils::modinv};
pub struct BSGSAttack {} // Потом можно добавить ограничения, типы и т.д.

enum AttackError {
    TooBigModulus,
    Cancelled { iterations: usize },
    NotApplicable { iterations: usize },
}

impl KeyExchangeAttack for BSGSAttack {
    fn name(&self) -> String {
        "Baby step giant step".to_string()
    }

    fn run(&self, cancel: Arc<AtomicBool>, seed: u64, public_data: KeyExchangePublicData) -> AttackReport {
        let (modulus, generator, alice_public_message, bob_public_message) = match public_data {
            KeyExchangePublicData::DiffieHellman { modulus, generator, alice_public_message, bob_public_message } => (modulus, generator, alice_public_message, bob_public_message),
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
                    "alice_public_message": alice_public_message.to_string(),
                    "bob_public_message": bob_public_message.to_string(),
                })
            }
        };

        // TODO - дублирующийся код
        let (alice_secret, iterations_for_alice) = match Self::decode(&cancel, &modulus, &generator, &alice_public_message) {
            Ok(v) => v,
            Err(e) => {
                match e {
                    AttackError::Cancelled { iterations } => return make_report(iterations as u64, AttackResult::Cancelled),
                    AttackError::NotApplicable { iterations } => return make_report(iterations as u64, AttackResult::Failed { reason: "Не удалось найти секрет Алисы".to_string() }),
                    AttackError::TooBigModulus => return make_report(0, AttackResult::Failed { reason: "Слишком большой модуль для перебора".to_string() }),
                }
            }
        };

        let shared = bob_public_message.modpow(&alice_secret, &modulus);

        make_report(iterations_for_alice as u64, AttackResult::Success { message: shared.to_string() })
    }
}

impl BSGSAttack {
    pub fn new() -> BSGSAttack{
        BSGSAttack {}
    }

    // TODO - Переименовать
    fn decode(cancel: &Arc<AtomicBool>, modulus: &BigUint, generator: &BigUint, public_message: &BigUint) -> Result<(BigUint, usize), AttackError> {
        let mut iterations: usize = 0;

        let modulus_minus_one = modulus - BigUint::one();

        let sqrt_value = modulus_minus_one.sqrt();
        let mut m = match sqrt_value.to_usize() {
            Some(v) => v,
            None => return Err(AttackError::TooBigModulus),
        };

        if &sqrt_value * &sqrt_value < modulus_minus_one {
            m += 1;
        }

        m += 1;

        let mut baby_steps = HashMap::<BigUint, usize>::new();

        let mut current = BigUint::one();

        for j in 0..m {
            if iterations % 100 == 0 {
                if cancel.load(Ordering::Relaxed) {
                    return Err(AttackError::Cancelled { iterations });
                }
            }

            baby_steps.entry(current.clone()).or_insert(j);

            current = (&current * generator) % modulus;
            iterations += 1;
        }

        let g_to_m = generator.modpow(&BigUint::from(m), modulus);

        let g_to_minus_m = match modinv(&g_to_m.to_bigint().unwrap(), &modulus.to_bigint().unwrap()) {
            Some(value) => match value.to_biguint() {
                Some(v) => v,
                None => return Err(AttackError::NotApplicable { iterations }),
            },
            None => return Err(AttackError::NotApplicable { iterations }),
        };

        let mut gamma = public_message.clone();

        for i in 0..m {
            if cancel.load(Ordering::Relaxed) {
                return Err(AttackError::Cancelled { iterations });
            }

            if let Some(j) = baby_steps.get(&gamma) {
                let secret = i * m + j;
                return Ok((BigUint::from(secret), iterations));
            }

            gamma = (&gamma * &g_to_minus_m) % modulus;
            iterations += 1;
        }

        Err(AttackError::NotApplicable { iterations })
    }
}