use crate::{
    attack::{BruteForceFactorizationAttack, SmallExponentAttack, AttackFactory},
    cryptocode::{Algorithm, RsaToy},
    utils::{generate_seed_u64, read_line, read_usize, save_report, welcome_print, print_algorithms, clear_console}
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

    welcome_print();

    let algorithms_len_handler = |v: usize| { if v <= allowed_algorithms.len() { Some(v) } else { None } };
    let primes_len_handler = |v: usize| { if v >= 8 { Some(v)} else { None } };

    loop {
        print_algorithms(&allowed_algorithms);
        let mut seed = generate_seed_u64();
        let choice: usize = read_usize("\nВведите номер интересующего алгоритма для проведения атак:", algorithms_len_handler);
        if choice == 0 {
            break;
        }

        let seeded_algorithm_choice = read_line(Some("\nХотите ли Вы использовать определенный seed? (Y/N)"));
        if seeded_algorithm_choice == "Y".to_string() {
            seed = read_usize("\nВведите seed", |v| Some(v)) as u64;
        }

        let primes_length: usize = read_usize("\nВведите желаемую длину простых чисел множителей не менее 8 (в битах)", primes_len_handler);
        
        let rsa = RsaToy::new(primes_length, seed);
        rsa.print_public_parameters(); 
        let message = read_line(Some("Введите сообщение, которое хотите зашифровать"));
        let encoded_values = rsa.encode(&message);
        // Пока не будем это показывать, потому что я не совсем понимаю как это лучше всего делать и зачем
        //println!("Закодированное сообщение в виде HEX - {}", get_utf8_representation(encoded_values.clone()));

        debug_assert!(rsa.decode(encoded_values.clone()) == message);

        // Суть - ересь. Не хочется это выносить в console_helper, потому что хочется простого добавления алгоритмов,
        // но в то же время пока не понимаю как грамотно связывать атаки и алгоритмы
        loop {
            println!("\nВыберите атаку (или введите 0 для выхода к алгоритмам)");
            let allowed_attacks: Vec<AttackFactory> = vec![|| Box::new(BruteForceFactorizationAttack::new()), || Box::new(SmallExponentAttack::new())];
            for (index, factory) in allowed_attacks.iter().enumerate() {
                let attack = factory();
                println!("{}) {}", index + 1, attack.name());
            }
            let attacks_len_handler = |v: usize| { if v <= allowed_attacks.len() { Some(v) } else { None } };
            let choice = read_usize("", attacks_len_handler);
            if choice == 0 {
                break;
            }
            let chosen_attack = allowed_attacks[choice - 1]();

            println!("\nПроизводим атаку...\n");
            let result = chosen_attack.run(&rsa.public_exponent, &rsa.modulus, &encoded_values, seed);
            println!("{}", &result);
            match save_report(&result, format!("{}.json", RsaToy::name())) {
                Ok(v) => v,
                Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
            };
        }

        clear_console();
    }

    println!("Выход из песочницы");
}
