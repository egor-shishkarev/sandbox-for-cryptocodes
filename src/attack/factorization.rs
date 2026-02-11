use std::time::{Duration, Instant};

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{ToPrimitive, Zero, One};
use num_integer::{Integer, Roots};

pub trait Attack {
    fn name() -> &'static str;
    fn run(&mut self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>);
    fn iterations_explain() -> &'static str;
}

#[derive(Debug)]
pub struct BruteForceFactorizationAttack {
    pub time: Duration,
    pub iterations: BigUint,
    pub result: String,
}

impl Attack for BruteForceFactorizationAttack {
    fn name() -> &'static str {
        "Атака факторизацией (brute force)"
    }

    fn iterations_explain() -> &'static str {
        "Количество повторов цикла в которых мы раскладываем modulus на множители"
    }

    // TODO - сюда нужно передавать Oracle, чтобы было нагляднее, что между шифрованием и атакой есть только конкретно эти значения.
    // Короче обеспечить обособленность друг от друга
    fn run(&mut self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>) {
        // Нужно просто :) факторизовать modulus, то есть разобрать на два множителя.
        let start = Instant::now();
        let (p, q, iterations) = match Self::factorize(modulus.clone()) {
            Some(v) => v,
            None => {
                println!("Слишком большое значение для перебора");
                return
            }
        };
        let phi = (p - 1) * (q - 1);
        let d = Self::modinv(&public_exponent.to_bigint().unwrap(), &BigInt::from(phi)).unwrap();

        let decoded_message = Self::decode(d.to_biguint().unwrap(), modulus.clone(), ciphertext);
        self.iterations = BigUint::from(iterations);
        self.result = decoded_message;
        self.time = start.elapsed();
    }
}

impl BruteForceFactorizationAttack {
    pub fn new() -> BruteForceFactorizationAttack{
        BruteForceFactorizationAttack {
            time: Duration::ZERO,
            iterations: BigUint::zero(),
            result: String::from(""), // Option лучше сделать
        }
    }

    fn factorize(modulus: BigUint) -> Option<(usize, usize, usize)> {
        let end_range: usize = match modulus.sqrt().to_usize() {
            Some(v) => v,
            None => {
                0
            },
        };

        let mut first_prime: usize = 0;
        let mut second_prime: usize = 0;

        for i in (3..=end_range).step_by(2) {
            if &modulus % i == BigUint::zero() {
                first_prime = i;
                second_prime = (&modulus / i).to_usize().unwrap();
            }
        }

        if first_prime == 0 || second_prime == 0 {
            return None
        }

        Some((first_prime, second_prime, first_prime - 3))
    }

    // TODO - встречается в двух местах
    fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let (g, x, _) = Self::egcd(a.clone(), m.clone());
        if g != BigInt::one() {
            return None;
        }
        Some((x % m + m) % m)
    }

    fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a, BigInt::one(), BigInt::zero());
        }
        let q = &a / &b;
        let r = &a % &b;
        let (g, x1, y1) = Self::egcd(b.clone(), r);
        let x = y1.clone();
        let y = x1 - q * y1;
        (g, x, y)
    }

    fn decode(private_exponent: BigUint, modulus: BigUint, bytes: &Vec<Vec<u8>>) -> String {
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in bytes {
            let number =  BigUint::from_bytes_be(&value);
            let decoded_value = number.modpow(&private_exponent, &modulus);

            let block = decoded_value.to_bytes_be();
            decoded_values.extend(block);
        }

        println!("{:?}", decoded_values);

        String::from_utf8(decoded_values).unwrap()
    }
}