use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::Duration};
use crossbeam_channel::unbounded;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::{
    algorithms::{AlgorithmFactory, AlgorithmType, Ciphertext, DifficultyLevel, DiffieHellmanToy, ElGamalToy, EncryptionAlgorithmKind, EncryptionPublicData, KeyExchangePublicData, Message, RsaToy, dh_factory, elgamal_factory, rsa_factory},
    attack::{
        EncryptionAttackFactory, KeyExchangeAttackFactory,
        diffie_hellman::{BSGSAttack, BruteForceDiffieHellmanAttack},
        elgamal::{BruteForceElGamalAttack, PohligHellmanAttack},
        rsa::{BruteForceFactorizationAttack, FermatFactorizationAttack, SmallExponentAttack}
    },
    attack_report::AttackReport,
    utils::{UiMsg, clear_console, generate_seed_u64, print_algorithms, random_in_range, read_biguint_from_ui, read_from_ui, read_usize_from_ui, rng_from_seed, save_report, spawn_input_thread, welcome_print}
};
mod attack;
mod attack_report;
mod algorithms;
mod utils;

fn main() {
    let allowed_algorithms: Vec<(&str, AlgorithmFactory)> = vec![
        ("RSA", rsa_factory),
        ("Diffie-Hellman", dh_factory),
        ("El Gamal", elgamal_factory)
    ];

    welcome_print();

    let algorithms_len_handler = |v: usize| v <= allowed_algorithms.len();
    let difficulty_handler = |v: usize| v >= DifficultyLevel::MIN && v <= DifficultyLevel::MAX;

    let (ui_tx, ui_rx) = unbounded::<UiMsg>();
    spawn_input_thread(ui_tx);

    loop {
        clear_console();
        print_algorithms(&allowed_algorithms);
        let mut seed = generate_seed_u64();
        let choice: usize = read_usize_from_ui(&ui_rx,"\nВведите номер интересующего алгоритма для проведения атак:", algorithms_len_handler);
        if choice == 0 {
            break;
        }

        let seeded_algorithm_choice = read_from_ui(&ui_rx, "\nХотите ли Вы использовать определенный seed? (Y/N)");
        if seeded_algorithm_choice == "Y".to_string() {
            seed = read_usize_from_ui(&ui_rx,"\nВведите seed", |_v| true) as u64;
        }

        let (_, factory) = &allowed_algorithms[choice - 1];

        // Естественно, это всё относительно, взламывать RSA с 2048-битным ключом глупо для песочницы
        println!("\nВыберите уровень сложности шифрования (1-5):");
        println!("1 - Очень слабое");
        println!("2 - Слабое");
        println!("3 - Среднее");
        println!("4 - Сильное");
        println!("5 - Очень сильное");

        let difficulty_choice: usize = read_usize_from_ui(&ui_rx, "\nВведите уровень сложности:", difficulty_handler);
        let difficulty = DifficultyLevel::from_choice(difficulty_choice);

        let bits_for_difficulty = match choice {
            1 => RsaToy::bits_for_difficulty(difficulty),
            2 => DiffieHellmanToy::bits_for_difficulty(difficulty),
            3 => ElGamalToy::bits_for_difficulty(difficulty),
            _ => RsaToy::bits_for_difficulty(difficulty),
        };

        let algorithm = factory(seed, bits_for_difficulty);
    
        match algorithm {
            AlgorithmType::Encryption(algorithm) => {
                let kind = algorithm.kind();
                match kind {
                    EncryptionAlgorithmKind::Rsa => {
                        algorithm.print_public_parameters(); 
                        let message = read_from_ui(&ui_rx, "Введите сообщение, которое хотите зашифровать");
                        let ciphertext = match algorithm.encode(Message::Rsa(message.clone())) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Ошибка шифрования: {e}");
                                read_from_ui(&ui_rx, "\nНажмите Enter чтобы продолжить...");
                                continue;
                            }
                        };

                        let encoded_values: Vec<Vec<u8>> = match ciphertext {
                            Ciphertext::Rsa(v) => {
                                debug_assert!(algorithm.decode(Ciphertext::Rsa(v.clone())).is_ok_and(|s| s == message));
                                v
                            }
                            _ => Vec::new(),
                        };

                        let allowed_attacks: Vec<EncryptionAttackFactory> = vec![
                            || Box::new(BruteForceFactorizationAttack::new()),
                            || Box::new(SmallExponentAttack::new()),
                            || Box::new(FermatFactorizationAttack::new()),
                        ];

                        let algorithm_ref = algorithm.as_ref();
                        let rsa_public_data_builder = {
                            let encoded_values = encoded_values.clone();
                            move || algorithm_ref.get_public_data(Some(Ciphertext::Rsa(encoded_values.clone())))
                        };

                        run_attacks::<EncryptionPublicData, _, _>(&ui_rx, seed, algorithm_ref.name(), allowed_attacks, rsa_public_data_builder);
                    },
                    EncryptionAlgorithmKind::ElGamal => {
                        algorithm.print_public_parameters(); 
                        let k_constraint = match algorithm.get_public_data(None) {
                            algorithms::EncryptionPublicData::ElGamal { modulus, generator: _, key: _, ciphertext: _ } => modulus - BigUint::from(2u8),
                            _ => BigUint::zero(), //* Сюда не должны никогда заходить
                        };
                        let message = read_biguint_from_ui(&ui_rx, &format!("Введите число, которое хотите зашифровать (не более {})", k_constraint), |v| v < k_constraint);
                        let prompt = format!("\nВведите число k не большее {} или 0 для случайного выбора", k_constraint.to_string());
                        let mut k = BigUint::from(read_usize_from_ui(&ui_rx, &prompt, |v| BigUint::from(v) < k_constraint));
                        if k == BigUint::zero() {
                            let mut rng = rng_from_seed(seed);
                            k = random_in_range(&mut rng, &k_constraint);
                        }
                        let encoded_values = match algorithm.encode(Message::ElGamal{ message: BigUint::from(message.clone()), k }) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Ошибка шифрования: {e}");
                                read_from_ui(&ui_rx, "\nНажмите Enter чтобы продолжить...");
                                continue;
                            }
                        };
                        let (first_value, second_value) = match encoded_values {
                            Ciphertext::ElGamal { c1, c2 } => {
                                let decoded = algorithm.decode(Ciphertext::ElGamal{c1: c1.clone(), c2: c2.clone()});
                                debug_assert!(decoded.is_ok_and(|s| s == message.to_string()));
                                (c1, c2)
                            },
                            _ => (BigUint::zero(), BigUint::zero()), //* Сюда не должны никогда заходить
                        };

                        let allowed_attacks: Vec<EncryptionAttackFactory> = vec![
                            || Box::new(BruteForceElGamalAttack::new()),
                            || Box::new(PohligHellmanAttack::new()),
                        ];

                        let algorithm_ref = algorithm.as_ref();
                        let elgamal_public_data_builder = {
                            let first_value = first_value.clone();
                            let second_value = second_value.clone();
                            move || algorithm_ref.get_public_data(Some(Ciphertext::ElGamal { c1: first_value.clone(), c2: second_value.clone() }))
                        };

                        run_attacks::<EncryptionPublicData, _, _>(&ui_rx, seed, algorithm_ref.name(), allowed_attacks, elgamal_public_data_builder);
                    }
                }
            },
            AlgorithmType::KeyExchange(algorithm) => {
                algorithm.print_public_parameters();

                println!("Секретное общее значение - {}", algorithm.establish_shared_secret());

                let allowed_attacks: Vec<KeyExchangeAttackFactory> = vec![
                    || Box::new(BruteForceDiffieHellmanAttack::new()),
                    || Box::new(BSGSAttack::new()),
                ];

                let dh_public_data_builder = {
                    let algorithm_ref = algorithm.as_ref();
                    move || algorithm_ref.get_public_data()
                };

                run_attacks::<KeyExchangePublicData, _, _>(&ui_rx, seed, algorithm.name(), allowed_attacks, dh_public_data_builder);
            }
        }
    }

    println!("\nВыход из песочницы");
}

fn run_attacks<P, Factory, FBuild>(
    ui_rx: &crossbeam_channel::Receiver<UiMsg>,
    seed: u64,
    algorithm_name: &str,
    allowed_attacks: Vec<Factory>,
    build_public_data: FBuild,
) where
    P: Send + 'static,
    Factory: Fn() -> Box<dyn crate::attack::GenericAttack<P>>,
    FBuild: Fn() -> P,
{
    loop {
        println!("\nВыберите атаку (или введите 0 для выхода к алгоритмам)");
        for (index, factory) in allowed_attacks.iter().enumerate() {
            let attack = factory();
            println!("{}) {}", index + 1, attack.name());
        }
        let attacks_len_validator = |v: usize| v <= allowed_attacks.len();
        let choice = read_usize_from_ui(ui_rx, "", attacks_len_validator);
        if choice == 0 {
            break;
        }
        let chosen_attack = allowed_attacks[choice - 1]();

        println!("\nПроизводим атаку... (для прерывания атаки введите q + \"Enter\")\n");

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_attack = cancel.clone();

        let public_data = build_public_data();

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

        match save_report(&result, format!("{}.json", algorithm_name)) {
            Ok(v) => v,
            Err(_) => println!("\nНе удалось сохранить отчет в файл!\n"),
        };
    }
}
