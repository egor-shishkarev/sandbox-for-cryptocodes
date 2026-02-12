pub trait Algorithm {
    fn encode(&self, message: &str) -> Vec<Vec<u8>>; // В идеале Bytes, но пока хз как написать правильно
    fn decode(&self, bytes: Vec<Vec<u8>>) -> String;
    fn name() -> &'static str;
    fn print_public_parameters(&self);
    // TODO - нужно еще как-то получать публичные параметры, помимо их вывода.
    // Однако как сделать так, чтобы можно было получать параметры разных типов?
    // Даже с генериками это звучит пока не понятно
}
