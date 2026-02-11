mod utils;
mod console_helper;

pub use utils::get_utf8_representation;
// TODO - как-то разделить на обычные утилиты и консольные утилиты
pub use console_helper::{read_line, welcome_print};
