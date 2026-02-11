use crate::{console_helper::read_line, cryptocode::Algorithm};
use num_bigint::{self, BigUint};
use num_traits::Zero;
mod console_helper;
mod cryptocode;

fn main() {
    let allowed_algorithms: Vec<String> = [
        "1) RSA",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let choose = console_helper::welcome_print(allowed_algorithms);
    println!("Выбранный алгоритм - {}", choose);

    let rsa = cryptocode::RsaToy::new(64, BigUint::zero()); 
    println!("Значения для RSA - публичная экспонента - {}, n - {}", &rsa.public_exponent, &rsa.modulus);
    println!("Введите сообщение, которое хотите зашифровать => ");
    let message = read_line();
    let encoded_values = rsa.encode(&message);
    println!("\"Закодированное сообщение\" - {:?}", &encoded_values);
    let decoded_value = rsa.decode(encoded_values);
    println!("\"Раскодированное сообщение\" - {:?}", &decoded_value);
}


