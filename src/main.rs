use crate::{
    attack::{Attack, BruteForceFactorizationAttack},
    cryptocode::{Algorithm, RsaToy},
    utils::{get_utf8_representation, read_line, read_usize, welcome_print, generate_seed_u64}
};
mod attack;
mod attack_report;
mod cryptocode;
mod utils;


// TODO - переименовать файлы в папках, лучше чтобы они не совпадали с названиями папок
fn main() {
    let allowed_algorithms: Vec<String> = [
        RsaToy::name(),
    ]
    .into_iter()
    .map(String::from)
    .collect();

    welcome_print(&allowed_algorithms);

    let algorithms_len_handler = |v: usize| { if v <= allowed_algorithms.len() { Some(v) } else { None } };
    let primes_len_handler = |v: usize| { if v >= 8 { Some(v)} else { None } };

    loop {
        let seed = generate_seed_u64();
        let choice: usize = read_usize("Введите номер интересующего алгоритма для проведения атак:", algorithms_len_handler);
        if choice == 0 {
            break;
        }

        let primes_length: usize = read_usize("Введите желаемую длину простых чисел множителей не менее 8 (в битах)", primes_len_handler);
        
        let rsa = RsaToy::new(primes_length, seed);
        rsa.print_public_parameters(); 
        let message = read_line(Some("Введите сообщение, которое хотите зашифровать => "));
        let encoded_values = rsa.encode(&message);
        println!("Закодированное сообщение в виде HEX - {}", get_utf8_representation(encoded_values.clone()));

        debug_assert!(rsa.decode(encoded_values.clone()) == message);

        println!("Производим атаку на открытый ключ");
        let mut brute_force_factorization_attack = BruteForceFactorizationAttack::new();
        let result = brute_force_factorization_attack.run(&rsa.public_exponent, &rsa.modulus, &encoded_values, seed);
        println!("Результат атаки - {:?}", &result);
    }

    println!("Завершение программы");
}
