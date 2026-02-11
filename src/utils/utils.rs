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
