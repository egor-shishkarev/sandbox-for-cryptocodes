use num_bigint::{BigInt, BigUint};
use num_traits::{Zero, One};
use rand::SeedableRng;
use rand_core::{OsRng, RngCore};
use rand_chacha::ChaCha20Rng;
use num_prime::{RandPrime, PrimalityTestConfig};

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a, BigInt::one(), BigInt::zero());
    }
    let q = &a / &b;
    let r = &a % &b;
    let (g, x1, y1) = egcd(b.clone(), r);
    let x = y1.clone();
    let y = x1 - q * y1;
    (g, x, y)
}

pub fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = egcd(a.clone(), m.clone());
    if g != BigInt::one() {
        return None;
    }
    Some((x % m + m) % m)
}

pub fn generate_seed_u64() -> u64 {
    OsRng.next_u64()
}

pub fn rng_from_seed(seed: u64) -> ChaCha20Rng {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    ChaCha20Rng::from_seed(s)
}

pub fn generate_two_distinct_primes(seed: u64, bits: usize)-> (BigUint, BigUint) {
    //? По идее на каждый запрос на кодирование нужно делать свой seed, поэтому можно просто здесь принимать seed и создавать тут же RNG

    let mut rng = rng_from_seed(seed);

    let config = Some(PrimalityTestConfig::bpsw());

    let p: BigUint = rng.gen_prime_exact(bits, config.clone());
    let mut q: BigUint;

    loop {
        q = rng.gen_prime_exact(bits, config.clone());
        if q != p {
            break;
        }
    }

    (p, q)
}
