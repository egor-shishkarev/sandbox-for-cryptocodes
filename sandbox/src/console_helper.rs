pub fn welcome_print(allowed_algorithms: Vec<String>) -> String {
    println!("Добро пожаловать в песочницу для атак на криптокоды!\n");
    println!("Доступные алгоритмы для кодирования:");
    for algorithm in allowed_algorithms {
        println!("{algorithm}");
    }

    println!("Введите номер интересующего алгоритма для проведения атак:");
    read_line()
}

pub fn read_line() -> String {
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).expect("Не удалось прочитать ввод");

    buffer.trim().to_string()
}
