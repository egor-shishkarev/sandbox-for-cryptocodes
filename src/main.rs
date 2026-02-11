use std::usize::MAX;

use crate::{attack::{Attack, BruteForceFactorizationAttack}, utils::{read_line, welcome_print}, cryptocode::{Algorithm, RsaToy}, utils::get_utf8_representation};
use num_bigint::{self, BigUint};
use num_traits::Zero;
mod attack;
mod cryptocode;
mod utils;

fn main() {
    let allowed_algorithms: Vec<String> = [
        RsaToy::name(),
    ]
    .into_iter()
    .map(String::from)
    .collect();

    welcome_print(&allowed_algorithms);

    loop {
        let mut choice: usize = MAX;
        loop {
            let input = read_line(Some("Введите номер интересующего алгоритма для проведения атак:"));
            choice = match input.trim().parse() {
                Ok(v) => {
                    if v > allowed_algorithms.len() {
                        println!("Введено некорректное значение, повторите ввод");
                        continue;
                    }
                    v
                },
                Err(_) => {
                    println!("Введено некорректное значение, повторите ввод");
                    continue;
                }
            };
            break;
        }
        
        if choice == 0 {
            break;
        }

        let mut primes_length: usize = MAX;
            
        // TODO - переиспользовать
        loop {
            let input = read_line(Some("Введите желаемую длину простых чисел множителей не менее 8 (в битах)"));
            primes_length = match input.trim().parse() {
                Ok(v) => {
                    if v < 8 {
                        println!("Введено слишком маленькое значение, попробуйте ввести значение больше 8");
                        continue;
                    }
                    v
                },
                Err(_) => {
                    println!("Введено некорректное значение, повторите ввод");
                    continue;
                }
            };
            break;
        }

        
        let rsa = cryptocode::RsaToy::new(primes_length, BigUint::zero()); 
        let message = read_line(Some("Введите сообщение, которое хотите зашифровать => "));
        let encoded_values = rsa.encode(&message);
        println!("Закодированное сообщение в виде HEX - {}", get_utf8_representation(encoded_values.clone()));

        debug_assert!(rsa.decode(encoded_values.clone()) == message);

        println!("Производим атаку на открытый ключ");
        let mut brute_force_factorization_attack = BruteForceFactorizationAttack::new();
        brute_force_factorization_attack.run(&rsa.public_exponent, &rsa.modulus, &encoded_values);
        println!("Результат атаки - {:?}", &brute_force_factorization_attack);
    }

    println!("Завершение программы");
}
