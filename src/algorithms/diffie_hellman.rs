use std::usize;

use num_bigint::BigUint;
use num_traits::{Zero, One, ToPrimitive};
use rand_chacha::ChaCha20Rng;

use crate::utils::{generate_safe_prime, random_in_range, rng_from_seed};

use super::algorithms_traits::KeyExchangeAlgorithm;

pub struct Party {
    pub public_message: BigUint,
    secret: BigUint,
}

pub struct DiffieHellmanToy {
    pub modulus: BigUint,
    pub generator: BigUint,
    pub alice: Party,
    pub bob: Party,
}

// Можно еще сделать создание алгоритма с нужными параметрами, допустим длина секретов и т.д.
impl KeyExchangeAlgorithm for DiffieHellmanToy {
    fn establish_shared_secret(&self) {
        let alice_shared = self.bob.public_message.modpow(&self.alice.secret, &self.modulus);
        let bob_shared = self.alice.public_message.modpow(&self.bob.secret, &self.modulus);

        debug_assert_eq!(alice_shared, bob_shared);
        
        alice_shared;
    }

    fn name() -> &'static str {
        "Diffie-Hellman"
    }

    fn print_public_parameters(&self) {
        println!("\nДлина ключа (модуля) в битах - {}", &self.modulus.to_bytes_be().len() * 8);
        println!("Публичные данные - ({}, {})\n", &self.modulus, &self.generator);
        println!("Сообщение от Алисы - {}", &self.alice.public_message);
        println!("Сообщение от Боба - {}", &self.bob.public_message);
    }
}

impl DiffieHellmanToy {
    pub fn new(seed: u64, prime_length: usize) -> DiffieHellmanToy {
        let mut rng = rng_from_seed(seed);
        let (modulus, generator, q) = Self::generate_public_params(&mut rng, prime_length);
        let alice_secret = random_in_range(&mut rng, &q);
        let bob_secret = random_in_range(&mut rng, &q);

        let alice_message = generator.modpow(&alice_secret, &modulus);
        let bob_message = generator.modpow(&bob_secret, &modulus);

        DiffieHellmanToy {
            modulus: modulus.clone(),
            generator,
            alice: Party { secret: alice_secret.clone(), public_message: alice_message.clone() },
            bob: Party { secret: bob_secret.clone(), public_message: bob_message.clone() },
            // shared_secret: Self::generate_shared_secret(&bob_message, &alice_secret, &modulus),
        }
    }

    fn generate_shared_secret(public_message: &BigUint, secret: &BigUint,modulus:&BigUint) -> BigUint {
        public_message.modpow(secret, &modulus)
    }

    fn generate_public_params(rng: &mut ChaCha20Rng, prime_length: usize) -> (BigUint, BigUint, BigUint) {
        let (modulus, q) = generate_safe_prime(rng, prime_length);
        let generator = match Self::get_generator(&modulus, &q) {
            Some(v) => BigUint::from(v),
            None => BigUint::zero(), // TODO - ну не ноль конечно же, но хз пока что сюда проставить
        };

        (modulus, generator, q)
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
