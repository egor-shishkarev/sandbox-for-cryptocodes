use num_integer::Integer;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero, ToPrimitive};

use super::cryptocode::Algorithm;

pub struct RsaToy {
    pub closed_exponent: Option<BigUint>, //TODO Ну тут конечно же не pub, пока для тестов просто, плюс Option хрень конечно
    pub open_exponent: BigUint,
    pub n: BigUint, // TODO переименовать
}


// Можно еще сделать создание алгоритма с нужными параметрами, допустим длина секретов и т.д.
impl Algorithm for RsaToy {
    fn encode(&self, message: &str) -> Vec<BigUint> {
        // Значит так, по идее разделяем на подсообщения по < n символов или байт и прогоняем алгоритм
        let bytes = message.as_bytes();
        let n = &self.n;
        let e = &self.open_exponent;
        // Надо поделить на чанки по < n байт

        println!("{:?}", bytes);

        let mut i: usize = 0;

        let mut encoded_bytes: Vec<BigUint> = Vec::new();

        loop {
            if i >= bytes.len() {
                break;
            }

            let two_bytes: BigUint;

            if i + 1 >= bytes.len() {
                two_bytes = BigUint::from(bytes[i]);
            } else {
                two_bytes = BigUint::from(bytes[i]) * BigUint::from(256u16) + BigUint::from(bytes[i + 1]);
            }

            // TODO - сделать нормально под каждый n. Возможно добавить padding и рандомную часть как в нормальном RSA
            if two_bytes < *n {
                let encoded_value = two_bytes.modpow(e, n);
                encoded_bytes.push(encoded_value);
                i += 2;
            } else {
                let encoded_value = BigUint::from(bytes[i]).modpow(e, n);
                encoded_bytes.push(encoded_value);
                i += 1;
            }
        }

        encoded_bytes // TODO - переводить в байты или что-то типа того. Надо посмотреть как настоящий RSA это делает
    }

    fn decode(&self, bytes: Vec<BigUint>) -> String {
        let mut decoded_values: Vec<u8> = Vec::new();

        for value in bytes {
            let decoded_value = value.modpow(&self.closed_exponent.clone().unwrap(), &self.n);

            if decoded_value < BigUint::from(256u16) {
                decoded_values.push(decoded_value.to_u8().unwrap());
            } else {
                let b0 = (&decoded_value / BigUint::from(256u16)).to_u8().unwrap();
                let b1 = (&decoded_value % BigUint::from(256u16)).to_u8().unwrap();
                decoded_values.push(b0);
                decoded_values.push(b1);
            }
        }

        String::from_utf8(decoded_values).unwrap()
    }

    fn name() -> &'static str {
        "AES"
    }

    fn id() -> u8 {
        1
    }
}

impl RsaToy {
    pub fn new(primes_length: usize) -> RsaToy {
        let (d, e, n) = Self::generate_secret_key(primes_length);
        RsaToy {
            closed_exponent: Some(d),
            open_exponent: e,
            n,
        }
    }

    fn generate_secret_key(primes_length: usize) -> (BigUint, BigUint, BigUint) {
        // генерируем два простых числа p и q не равных; n = p * q.
        let p_bits = num_primes::Generator::new_prime(primes_length).to_bytes_be();
        let q_bits = num_primes::Generator::new_prime(primes_length).to_bytes_be();
        let p = BigUint::from_bytes_be(&p_bits); // TODO: seed для воспроизводимости
        let q = BigUint::from_bytes_be(&q_bits);// TODO: seed для воспроизводимости

        let phi = (p.clone() - 1u32) * (q.clone() - 1u32);
        let _n = p * q;

        let mut open_exponent: Option<BigUint> = None;
        for candidate in [BigUint::from(3u8), BigUint::from(5u8), BigUint::from(17u8), BigUint::from(257u16)] {
            if phi.gcd(&candidate) == BigUint::from(1u8) {
                open_exponent = Some(candidate);
                break;
            }
        }
        let open_exponent = open_exponent.expect("No suitable open exponent found");

        let d = Self::modinv(&BigInt::from(open_exponent.clone()), &BigInt::from(phi.clone()))
            .and_then(|x| x.to_biguint())
            .expect("modinv failed");

        (d, open_exponent, _n)
        
    }

    fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a, BigInt::one(), BigInt::zero());
        }
        let q = &a / &b;
        let r = &a % &b;
        let (g, x1, y1) = Self::egcd(b.clone(), r);
        let x = y1.clone();
        let y = x1 - q * y1;
        (g, x, y)
    }

    fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let (g, x, _) = Self::egcd(a.clone(), m.clone());
        if g != BigInt::one() {
            return None;
        }
        Some((x % m + m) % m)
    }
}
