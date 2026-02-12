use crate::{
    attack::{Attack, BruteForceFactorizationAttack},
    cryptocode::{Algorithm, RsaToy},
    utils::{generate_seed_u64, read_line, read_usize, save_report, welcome_print}
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
        let mut seed = generate_seed_u64();
        let choice: usize = read_usize("Введите номер интересующего алгоритма для проведения атак:", algorithms_len_handler);
        if choice == 0 {
            break;
        }

        let seeded_algorithm_choice = read_line(Some("Хотите ли Вы использовать определенный seed? (Y/N) => "));
        if seeded_algorithm_choice == "Y".to_string() {
            seed = read_usize("Введите seed", |v| Some(v)) as u64;
        }

        let primes_length: usize = read_usize("Введите желаемую длину простых чисел множителей не менее 8 (в битах)", primes_len_handler);
        
        let rsa = RsaToy::new(primes_length, seed);
        rsa.print_public_parameters(); 
        let message = read_line(Some("Введите сообщение, которое хотите зашифровать => "));
        let encoded_values = rsa.encode(&message);
        // Пока не будем это показывать, потому что я не совсем понимаю как это лучше всего делать и зачем
        //println!("Закодированное сообщение в виде HEX - {}", get_utf8_representation(encoded_values.clone()));

        debug_assert!(rsa.decode(encoded_values.clone()) == message);

        println!("\nПроизводим атаку на открытый ключ...\n");
        let mut brute_force_factorization_attack = BruteForceFactorizationAttack::new();
        let result = brute_force_factorization_attack.run(&rsa.public_exponent, &rsa.modulus, &encoded_values, seed);
        println!("{}", &result);
        match save_report(&result, format!("{}.json", RsaToy::name())) {
            Ok(v) => v,
            Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
        };
    }

    println!("Выход из песочницы");
}
