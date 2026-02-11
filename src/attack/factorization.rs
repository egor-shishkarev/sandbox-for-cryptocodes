use std::{iter, time::Instant};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{ToPrimitive, Zero};
use crate::{attack_report::{AttackReport, AttackResult}, utils::modinv};

pub trait Attack {
    fn name(&self) -> &'static str;
    fn run(&mut self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>) -> AttackReport;
    fn iterations_explain(&self) -> &'static str;
}

pub struct BruteForceFactorizationAttack {} // Потом можно добавить ограничения, типы и т.д.

impl Attack for BruteForceFactorizationAttack {
    fn name(&self) -> &'static str {
        "Атака факторизацией (brute force)"
    }

    fn iterations_explain(&self) -> &'static str {
        "Количество повторов цикла в которых мы раскладываем modulus на множители"
    }

    // TODO - сюда нужно передавать Oracle, чтобы было нагляднее, что между шифрованием и атакой есть только конкретно эти значения.
    // Короче обеспечить обособленность друг от друга
    fn run(&mut self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>) -> AttackReport {
        // Нужно просто :) факторизовать modulus, то есть разобрать на два множителя.
        let start = Instant::now();
        let (p, q, iterations) = match Self::factorize(modulus.clone()) {
            Some(v) => v,
            None => {
                return AttackReport {
                    attack_name: Self::name(&self),
                    duration: Instant::now().elapsed(), // TODO - не уверен, что тут 0 будет, а надо бы 0
                    iterations: 0,
                    result: AttackResult::Failed { reason: String::from("Слишком большое значение для перебора") },
                    seed: BigUint::zero(),
                }
            }
        };
        let phi = (p - 1) * (q - 1);
        let d = modinv(&public_exponent.to_bigint().unwrap(), &BigInt::from(phi)).unwrap();

        let decoded_message = Self::decode(d.to_biguint().unwrap(), modulus.clone(), ciphertext);
        AttackReport {
            attack_name: Self::name(&self),
            duration: start.elapsed(),
            iterations: iterations as u64,
            result: AttackResult::Success { message: decoded_message },
            seed: BigUint::zero(),
        }
    }
}

impl BruteForceFactorizationAttack {
    pub fn new() -> BruteForceFactorizationAttack{
        BruteForceFactorizationAttack {}
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