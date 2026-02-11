pub trait Algorithm {
    fn encode(&self, message: &str) -> Vec<Vec<u8>>; // В идеале Bytes, но пока хз как написать правильно
    fn decode(&self, bytes: Vec<Vec<u8>>) -> String;
    fn name() -> &'static str;
    fn id() -> u8;
}
