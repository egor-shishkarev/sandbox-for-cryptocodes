use std::io::Write;
use crossterm::{
    execute,
    terminal::{Clear, ClearType},
    cursor::MoveTo,
};
use std::io::stdout;
use crossbeam_channel::Receiver;

use crate::{algorithms::{AlgorithmFactory}, utils::UiMsg};

pub fn welcome_print() {
    println!("Добро пожаловать в песочницу для атак на криптокоды!");
    println!("Для выхода введите 0 при выборе алгоритма\n");
    
}

pub fn print_algorithms(allowed_algorithms: &Vec<(&str, AlgorithmFactory)>) {
    // TODO - мб перенести сюда всю логику по получению всех алгоритмов?
    println!("Доступные алгоритмы для кодирования:");
    let mut index: u8 = 1;
    for algorithm in allowed_algorithms {
        println!("{}) {}", index, algorithm.0);
        index += 1;
    }
}

// TODO - сделать одну функцию для чтения с генериком и опциональной валидацией
pub fn read_from_ui(rx: &Receiver<UiMsg>, prompt: &str) -> String {
    loop {
        println!("{}", prompt);
        print!("> ");
        std::io::stdout().flush().unwrap();
        if let Ok(UiMsg::Line(line)) = rx.recv() {
            let s = String::from(line.trim());
            return s;
        }
        println!("Введено некорректное значение, повторите ввод");
    }
}

pub fn read_usize_from_ui(rx: &Receiver<UiMsg>, prompt: &str, validate: impl Fn(usize)->bool) -> usize {
    loop {
        println!("{}", prompt);
        print!("> ");
        std::io::stdout().flush().unwrap();
        if let Ok(UiMsg::Line(line)) = rx.recv() {
            let s = line.trim();
            if let Ok(v) = s.parse::<usize>() {
                if validate(v) { return v; }
            }
        }
        println!("Введено некорректное значение, повторите ввод");
    }
}

pub fn clear_console() {
    execute!(
        stdout(),
        Clear(ClearType::All),
        Clear(ClearType::Purge),
        MoveTo(0, 0)
    ).unwrap();
}

// pub fn get_utf8_representation(bytes_vector: Vec<Vec<u8>>) -> String {
//     let mut representation = String::new();

//     for vector in bytes_vector {
//         for byte in vector {
//             representation.push_str(&format!("{:02X} ", byte));
//         }

//     }

//     representation.pop();
//     representation
// }