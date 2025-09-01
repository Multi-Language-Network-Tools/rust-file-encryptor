use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex::{encode, decode};
use std::fs;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn encrypt_file(input_path: &str, output_path: &str, key: &[u8; 32], iv: &[u8; 16]) {
    let data = fs::read(input_path).expect("Failed to read input file");
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(&data);
    fs::write(output_path, encode(ciphertext)).expect("Failed to write encrypted file");
    println!("File encrypted and saved to {}", output_path);
}

fn decrypt_file(input_path: &str, output_path: &str, key: &[u8; 32], iv: &[u8; 16]) {
    let data = fs::read_to_string(input_path).expect("Failed to read encrypted file");
    let ciphertext = decode(data).unwrap();
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&ciphertext).unwrap();
    fs::write(output_path, decrypted_data).expect("Failed to write decrypted file");
    println!("File decrypted and saved to {}", output_path);
}

fn main() {
    let key = b"01234567890123456789012345678901"; // 32 bytes
    let iv = b"0123456789012345"; // 16 bytes

    encrypt_file("test.txt", "test.enc", key, iv);
    decrypt_file("test.enc", "test_decrypted.txt", key, iv);
}
