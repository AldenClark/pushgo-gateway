use super::encode_lower_hex_128;

#[inline]
pub fn random_id_bytes_128() -> [u8; 16] {
    rand::random()
}

#[inline]
pub fn generate_hex_id_128() -> String {
    let bytes = random_id_bytes_128();
    encode_lower_hex_128(&bytes)
}
