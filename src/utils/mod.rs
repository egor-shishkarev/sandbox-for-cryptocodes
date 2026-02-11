mod crypto;
mod console_helper;

pub use crypto::{modinv, generate_seed_u64, generate_two_distinct_primes};
pub use console_helper::{read_line, welcome_print, read_usize, get_utf8_representation};
