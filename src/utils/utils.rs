use num_bigint::BigInt;
use num_traits::{Zero, One};

pub fn get_utf8_representation(bytes_vector: Vec<Vec<u8>>) -> String {
    let mut representation = String::new();

    for vector in bytes_vector {
        for byte in vector {
            representation.push_str(&format!("{:02X} ", byte));
        }

    }

    representation.pop();
    representation
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a, BigInt::one(), BigInt::zero());
    }
    let q = &a / &b;
    let r = &a % &b;
    let (g, x1, y1) = egcd(b.clone(), r);
    let x = y1.clone();
    let y = x1 - q * y1;
    (g, x, y)
}

pub fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = egcd(a.clone(), m.clone());
    if g != BigInt::one() {
        return None;
    }
    Some((x % m + m) % m)
}
