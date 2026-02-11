mod cryptocode;
mod rsa_toy;

// Реэкспорт, чтобы из main писать cryptocode::Algorithm и cryptocode::RsaToy
pub use cryptocode::Algorithm;
pub use rsa_toy::RsaToy;
