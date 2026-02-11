pub fn welcome_print(allowed_algorithms: &Vec<String>) {
    // TODO - мб перенести сюда всю логику по получению всех алгоритмов?
    println!("Добро пожаловать в песочницу для атак на криптокоды!");
    println!("Для выхода введите 0 при выборе алгоритма\n");
    println!("Доступные алгоритмы для кодирования:");
    let mut index: u8 = 1;
    for algorithm in allowed_algorithms {
        println!("{index}) {algorithm}");
        index += 1;
    }
}

pub fn read_line(message: Option<&'static str>) -> String {
    let message = message.unwrap_or("Введите значение =>");
    println!("{} ", message);
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).expect("Не удалось прочитать ввод");

    buffer.trim().to_string()
}
