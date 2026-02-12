use num_bigint::BigUint;
use crate::attack_report::AttackReport;

pub trait Attack {
    fn name(&self) -> String;
    fn run(&self, public_exponent: &BigUint, modulus: &BigUint, ciphertext: &Vec<Vec<u8>>, seed: u64) -> AttackReport; // TODO - Прокидывать сюда seed - бред. Нужно делать отдельный модуль с экспериментами, фабриками и т.д.
    // TODO - потом добавить куда-нибудь, потому что для разных алгоритмов итерация может включать в себя несколько действий.
    // fn iterations_explain(&self) -> &'static str;
}

pub type AttackFactory = fn() -> Box<dyn Attack>;