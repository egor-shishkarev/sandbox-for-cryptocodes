use std::io::Write;
use crossterm::{
    execute,
    terminal::{Clear, ClearType},
    cursor::MoveTo,
};
use std::io::stdout;

pub fn welcome_print() {
    println!("Добро пожаловать в песочницу для атак на криптокоды!");
    println!("Для выхода введите 0 при выборе алгоритма\n");
    
}

pub fn print_algorithms(allowed_algorithms: &Vec<String>) {
    // TODO - мб перенести сюда всю логику по получению всех алгоритмов?
    println!("Доступные алгоритмы для кодирования:");
    let mut index: u8 = 1;
    for algorithm in allowed_algorithms {
        println!("{index}) {algorithm}");
        index += 1;
    }
}

pub fn read_line(message: Option<&'static str>) -> String {
    match message {
        Some(v) => println!("{} ", v),
        None => {}
    }

    print!("> ");
    std::io::stdout().flush().unwrap();
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).expect("Не удалось прочитать ввод");

    buffer.trim().to_string()
}

pub fn read_usize<F>(prompt: &'static str, handler: F) -> usize
where 
    F: Fn(usize) -> Option<usize>,
{
    loop {
        let input = read_line(Some(prompt));

        let result: usize = match input.trim().parse::<usize>() {
            Ok(v) => {
                    match handler(v) {
                        Some(v) => v,
                        None => { 
                            println!("Введено некорректное значение, повторите ввод");
                            continue;
                        }
                }
            },
            Err(_) => { 
                println!("Введено некорректное значение, повторите ввод");
                continue;
            }
        };

        return result;
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