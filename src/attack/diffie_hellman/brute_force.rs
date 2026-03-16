use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use num_bigint::{BigUint};
use num_traits::{ToPrimitive, One};
use crate::{algorithms::{KeyExchangePublicData}, attack::attack_trait::{KeyExchangeAttack}, attack_report::{AttackReport, AttackResult}, utils::modinv};
pub struct BruteForceDiffieHellmanAttack {} // Потом можно добавить ограничения, типы и т.д.

enum AttackError {
    TooBigModulus,
    Cancelled { iterations: usize },
    NotApplicable { iterations: usize },
}

impl KeyExchangeAttack for BruteForceDiffieHellmanAttack {
    fn name(&self) -> String {
        "Brute force".to_string()
    }

    // fn iterations_explain(&self) -> &'static str {
    //     "Количество повторов цикла в которых мы раскладываем modulus на множители"
    // }

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

        // TODO - дублирующийся код
        // let (bob_secret, iterations_for_bob) = match Self::decode(&cancel, &modulus, &generator, &bob_public_message) {
        //     Ok(v) => v,
        //     Err(e) => {
        //         match e {
        //             AttackError::Cancelled { iterations } => return make_report(iterations as u64, AttackResult::Cancelled),
        //             AttackError::NotApplicable { iterations } => return make_report(iterations as u64, AttackResult::Failed { reason: "Не удалось найти секрет Боба".to_string() }),
        //             AttackError::TooBigModulus => return make_report(0, AttackResult::Failed { reason: "Слишком большой модуль для перебора".to_string() }),
        //         }
        //     }
        // };

        let shared = bob_public_message.modpow(&alice_secret, &modulus);

        make_report(iterations_for_alice as u64, AttackResult::Success { message: shared.to_string() })
    }
}

impl BruteForceDiffieHellmanAttack {
    pub fn new() -> BruteForceDiffieHellmanAttack{
        BruteForceDiffieHellmanAttack {}
    }

    // TODO - Переименовать
    /**
     * Ищем секретную часть - экспоненту
     */
    fn decode(cancel: &Arc<AtomicBool>, modulus: &BigUint, generator: &BigUint, public_message: &BigUint) -> Result<(BigUint, usize), AttackError> {
        let mut iterations: usize = 0;
        let end_range: usize = match modulus.to_usize() {
            Some(v) => v,
            None => return Err(AttackError::TooBigModulus),
        };

        let mut cur = generator.modpow(&BigUint::one(), &modulus);

        for i in 1..end_range {
            iterations += 1;

            if iterations % 10000 == 0 {
                if cancel.load(Ordering::Relaxed) {
                    return Err(AttackError::Cancelled { iterations });
                }
            }

            if &cur == public_message {
                return Ok((BigUint::from(i), iterations));
            }

            // следующий шаг: g^(x+1) = g^x * g
            cur = (&cur * generator) % modulus;
        }

        Err(AttackError::NotApplicable { iterations })
    }
}