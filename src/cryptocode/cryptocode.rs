use num_bigint::BigUint;

pub trait Algorithm {
    fn encode(&self, message: &str) -> Vec<BigUint>; // В идеале Bytes, но пока хз как написать правильно
    fn decode(&self, bytes: Vec<BigUint>) -> String;
    fn name() -> &'static str;
    fn id() -> u8;
}

