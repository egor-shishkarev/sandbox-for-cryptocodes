pub fn welcome_print(allowed_algorithms: Vec<String>) {
    println!("Добро пожаловать в песочницу для атак на криптокоды!\n");
    println!("Доступные алгоритмы для кодирования:");
    for algorithm in allowed_algorithms {
        println!("{algorithm}");
    }
}

pub fn read_line(message: Option<&'static str>) -> String {
    let message = message.unwrap_or("Введите значение =>");
    println!("{} ", message);
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).expect("Не удалось прочитать ввод");

    buffer.trim().to_string()
}
