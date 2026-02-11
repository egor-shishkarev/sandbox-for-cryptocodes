use crate::{attack::{Attack, BruteForceFactorizationAttack}, console_helper::{read_line, welcome_print}, cryptocode::{Algorithm, RsaToy}};
use num_bigint::{self, BigUint};
use num_traits::Zero;
mod attack;
mod console_helper;
mod cryptocode;

fn main() {
    let allowed_algorithms: Vec<String> = [
        "1) RSA",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    welcome_print(allowed_algorithms);

    loop {
        let choice = read_line(Some("Введите номер интересующего алгоритма для проведения атак:"));
        if choice.trim() == "0" {
            break;
        }

        println!("Выбранный алгоритм - {}", choice);
        let primes_length: usize = read_line(Some("Введите желаемую длину простых чисел множителей (в битах)"))
            .trim()
            .parse()
            .expect("Введите целое число");
        let rsa = cryptocode::RsaToy::new(primes_length, BigUint::zero()); 
        println!("Значения для RSA - публичная экспонента - {}, n - {}", &rsa.public_exponent, &rsa.modulus);
        let message = read_line(Some("Введите сообщение, которое хотите зашифровать => "));
        let encoded_values = rsa.encode(&message);
        println!("\"Закодированное сообщение\" - {:?}", &encoded_values);
        println!("Закодированное сообщение в виде UTF8 - {}", RsaToy::get_utf8_representation(encoded_values.clone()));
        let decoded_value = rsa.decode(encoded_values.clone());
        println!("\"Раскодированное сообщение\" - {:?}", &decoded_value);

        println!("Производим атаку на открытый ключ и шифротекст");
        let mut bruteForceFactorizationAttack = BruteForceFactorizationAttack::new();
        bruteForceFactorizationAttack.run(&rsa.public_exponent, &rsa.modulus, &encoded_values);

        println!("Результат атаки - {:?}", &bruteForceFactorizationAttack);
    }

    println!("Завершение программы");
}
