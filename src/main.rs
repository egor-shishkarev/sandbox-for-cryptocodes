use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::Duration};
use crossbeam_channel::unbounded;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::{
    algorithms::{AlgorithmFactory, AlgorithmType, Ciphertext, EncryptionAlgorithmKind, Message, dh_factory, elgamal_factory, rsa_factory}, attack::{
        BruteForceFactorizationAttack, EncryptionAttackFactory, KeyExchangeAttackFactory, SmallExponentAttack, diffie_hellman::{BSGSAttack, BruteForceAttack}, rsa::FermatFactorizationAttack
    }, attack_report::AttackReport, utils::{UiMsg, clear_console, generate_seed_u64, print_algorithms, random_in_range, read_from_ui, read_usize_from_ui, rng_from_seed, save_report, spawn_input_thread, welcome_print}
};
mod attack;
mod attack_report;
mod algorithms;
mod utils;

// TODO - переименовать файлы в папках, лучше чтобы они не совпадали с названиями папок
fn main() {
    let allowed_algorithms: Vec<(&str, AlgorithmFactory)> = vec![
        ("RSA", rsa_factory),
        ("Diffie-Hellman", dh_factory),
        ("El Gamal", elgamal_factory)
    ];

    welcome_print();

    let algorithms_len_handler = |v: usize| v <= allowed_algorithms.len();
    let primes_len_handler = |v: usize| v >= 8;

    let (ui_tx, ui_rx) = unbounded::<UiMsg>();
    spawn_input_thread(ui_tx);

    loop {
        // TODO - рефакторинг. С первого взгляда я не понимаю что тут вообще происходит
        clear_console();

        print_algorithms(&allowed_algorithms);
        let mut seed = generate_seed_u64();
        let choice: usize = read_usize_from_ui(&ui_rx,"\nВведите номер интересующего алгоритма для проведения атак:", algorithms_len_handler);
        if choice == 0 {
            break;
        }

        // TODO - можно просто просить ввести сид, и если в воде не число, то брать рандомный сид
        let seeded_algorithm_choice = read_from_ui(&ui_rx, "\nХотите ли Вы использовать определенный seed? (Y/N)");
        if seeded_algorithm_choice == "Y".to_string() {
            seed = read_usize_from_ui(&ui_rx,"\nВведите seed", |_v| true) as u64;
        }

        // TODO - тут если честно хочется как-от переделать, потому что я хочу для DH делать меньшее ограничение, а для RSA 8 - уже мало
        let primes_length: usize = read_usize_from_ui(&ui_rx,"\nВведите желаемую длину простых чисел не менее 8 (в битах)", primes_len_handler);
        
        let (_, factory) = &allowed_algorithms[choice - 1];
        let algorithm = factory(seed, primes_length);
    
        match algorithm {
            AlgorithmType::Encryption(algorithm) => {
                let kind = algorithm.kind();
                match kind {
                    EncryptionAlgorithmKind::Rsa => {
                        algorithm.print_public_parameters(); 
                        let message = read_from_ui(&ui_rx, "Введите сообщение, которое хотите зашифровать");
                        let ciphertext = algorithm.encode(Message::Rsa(message.clone()));
                        // Пока не будем это показывать, потому что я не совсем понимаю как это лучше всего делать и зачем
                        //println!("Закодированное сообщение в виде HEX - {}", get_utf8_representation(encoded_values.clone()));

                        let mut encoded_values: Vec<Vec<u8>> = Vec::new();
                        match ciphertext {
                            Ciphertext::Rsa(v) => {
                                debug_assert!(algorithm.decode(Ciphertext::Rsa(v.clone())) == message);
                                encoded_values = v;
                            }
                            Ciphertext::ElGamal { c1, c2 } => {}
                        }
                        

                        // Суть - ересь. Не хочется это выносить в console_helper, потому что хочется простого добавления алгоритмов,
                        // но в то же время пока не понимаю как грамотно связывать атаки и алгоритмы
                        loop {
                            println!("\nВыберите атаку (или введите 0 для выхода к алгоритмам)");
                            let allowed_attacks: Vec<EncryptionAttackFactory> = vec![|| Box::new(BruteForceFactorizationAttack::new()), || Box::new(SmallExponentAttack::new()), || Box::new(FermatFactorizationAttack::new())];
                            for (index, factory) in allowed_attacks.iter().enumerate() {
                                let attack = factory();
                                println!("{}) {}", index + 1, attack.name());
                            }
                            let attacks_len_validator = |v: usize| v <= allowed_attacks.len();
                            let choice = read_usize_from_ui(&ui_rx, "", attacks_len_validator);
                            if choice == 0 {
                                break;
                            }
                            let chosen_attack = allowed_attacks[choice - 1]();

                            println!("\nПроизводим атаку... (для прерывания атаки введите q + \"Enter\")\n");

                            let cancel  = Arc::new(AtomicBool::new(false));
                            let cancel_for_attack = cancel.clone();

                            let public_data = algorithm.get_public_data(Some(Ciphertext::Rsa(encoded_values.clone())));
                            let attack_handle = thread::spawn(move || chosen_attack.run(cancel_for_attack, seed, public_data));
                            let result: AttackReport;

                            loop {
                                if attack_handle.is_finished() {
                                    result = attack_handle.join().unwrap();
                                    println!("{}", result);
                                    break;
                                }
                            
                                if let Ok(UiMsg::Line(line)) = ui_rx.try_recv() {
                                    let cmd = line.trim().to_lowercase();
                                    if cmd == "q" {
                                        cancel.store(true, Ordering::Relaxed);
                                    } else {
                                        println!("Во время атаки доступно только: q");
                                    }
                                }
                            
                                thread::sleep(Duration::from_millis(100));
                            }

                            match save_report(&result, format!("{}.json", algorithm.name())) {
                                Ok(v) => v,
                                Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
                            };
                        }
                    },
                    EncryptionAlgorithmKind::ElGamal => {
                        algorithm.print_public_parameters(); 
                        let k_constraint = match algorithm.get_public_data(None) {
                            algorithms::EncryptionPublicData::ElGamal { modulus, generator: _, key: _, ciphertext: _ } => modulus - BigUint::from(2u8),
                            _ => BigUint::zero(),
                        };
                        let message = read_usize_from_ui(&ui_rx, "Введите число, которое хотите зашифровать", |v| v > 0);
                        let prompt = format!("Введите число k не большее {} или 0 для случайного выбора", k_constraint.to_string());
                        let mut k = BigUint::from(read_usize_from_ui(&ui_rx, &prompt, |v| v >= 0 && BigUint::from(v) < k_constraint));
                        if k == BigUint::zero() {
                            let mut rng = rng_from_seed(seed);
                            k = random_in_range(&mut rng, &k_constraint);
                        }
                        let encoded_values = algorithm.encode(Message::ElGamal{ message: BigUint::from(message), k });
                        let  (c1, c2) = (BigUint::zero(), BigUint::zero());

                        match encoded_values {
                            Ciphertext::ElGamal { mut c1, mut c2 } => {
                                c1 = c1;
                                c2 = c2;
                                println!("({}, {})", c1, c2);
                                let decoded = algorithm.decode(Ciphertext::ElGamal{c1, c2});
                                println!("{}", decoded);
                                debug_assert!(decoded == message.to_string());
                            },
                            _ => {},
                        }
                
                        loop {
                            println!("\nВыберите атаку (или введите 0 для выхода к алгоритмам)");
                            let allowed_attacks: Vec<EncryptionAttackFactory> = vec![|| Box::new(BruteForceFactorizationAttack::new()), || Box::new(SmallExponentAttack::new()), || Box::new(FermatFactorizationAttack::new())];
                            for (index, factory) in allowed_attacks.iter().enumerate() {
                                let attack = factory();
                                println!("{}) {}", index + 1, attack.name());
                            }
                            let attacks_len_validator = |v: usize| v <= allowed_attacks.len();
                            let choice = read_usize_from_ui(&ui_rx, "", attacks_len_validator);
                            if choice == 0 {
                                break;
                            }
                            let chosen_attack = allowed_attacks[choice - 1]();

                            println!("\nПроизводим атаку... (для прерывания атаки введите q + \"Enter\")\n");

                            let cancel  = Arc::new(AtomicBool::new(false));
                            let cancel_for_attack = cancel.clone();

                            let public_data = algorithm.get_public_data(Some(Ciphertext::ElGamal { c1: c1.clone(), c2: c2.clone() }));
                            let attack_handle = thread::spawn(move || chosen_attack.run(cancel_for_attack, seed, public_data));
                            let result: AttackReport;

                            loop {
                                if attack_handle.is_finished() {
                                    result = attack_handle.join().unwrap();
                                    println!("{}", result);
                                    break;
                                }
                            
                                if let Ok(UiMsg::Line(line)) = ui_rx.try_recv() {
                                    let cmd = line.trim().to_lowercase();
                                    if cmd == "q" {
                                        cancel.store(true, Ordering::Relaxed);
                                    } else {
                                        println!("Во время атаки доступно только: q");
                                    }
                                }
                            
                                thread::sleep(Duration::from_millis(100));
                            }

                            match save_report(&result, format!("{}.json", algorithm.name())) {
                                Ok(v) => v,
                                Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
                            };
                        }
                    }
                }
            },
            AlgorithmType::KeyExchange(algorithm) => {
                algorithm.print_public_parameters();

                // TODO - можем печатать секрет, но не уверен, что надо, у нас все таки атака, а так мы уже знаем, что там
                println!("Секретное общее значение - {}", algorithm.establish_shared_secret());

                loop {
                    println!("\nВыберите атаку (или введите 0 для выхода к алгоритмам)");
                    let allowed_attacks: Vec<KeyExchangeAttackFactory> = vec![|| Box::new(BruteForceAttack::new()), || Box::new(BSGSAttack::new())];
                    for (index, factory) in allowed_attacks.iter().enumerate() {
                        let attack = factory();
                        println!("{}) {}", index + 1, attack.name());
                    }
                    let attacks_len_validator = |v: usize| v <= allowed_attacks.len();
                    let choice = read_usize_from_ui(&ui_rx, "", attacks_len_validator);
                    if choice == 0 {
                        break;
                    }
                    let chosen_attack = allowed_attacks[choice - 1]();

                    println!("\nПроизводим атаку... (для прерывания атаки введите q + \"Enter\")\n");

                    let cancel  = Arc::new(AtomicBool::new(false));
                    let cancel_for_attack = cancel.clone();

                    let public_data = algorithm.get_public_data();

                    let attack_handle = thread::spawn(move || chosen_attack.run(cancel_for_attack, seed, public_data));
                    let result: AttackReport;

                    loop {
                        if attack_handle.is_finished() {
                            result = attack_handle.join().unwrap();
                            println!("{}", result);
                            break;
                        }
                    
                        if let Ok(UiMsg::Line(line)) = ui_rx.try_recv() {
                            let cmd = line.trim().to_lowercase();
                            if cmd == "q" {
                                cancel.store(true, Ordering::Relaxed);
                            } else {
                                println!("Во время атаки доступно только: q");
                            }
                        }
                    
                        thread::sleep(Duration::from_millis(100));
                    }

                    match save_report(&result, format!("{}.json", algorithm.name())) {
                        Ok(v) => v,
                        Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
                    };
                }

            }
        }
    }

    println!("\nВыход из песочницы");
}
