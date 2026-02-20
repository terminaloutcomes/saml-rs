//! Content encryption for SAML assertions
//!
//! Implements A256CBC-HS512 (AES-256-CBC + HMAC-SHA-512) content encryption
//! as per XML Encryption specification.

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha512;

/// HMAC-SHA-512 for integrity checking
type HmacSha512 = Hmac<Sha512>;

/// Encrypts data using AES-256-CBC + HMAC-SHA-512
pub fn encrypt_a256cbs_hs512(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 64 {
        return Err("A256CBC-HS512 key must be 64 bytes".to_string());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".to_string());
    }

    // Extract HMAC key and encryption key from the master key
    let hmac_key = &key[..32];
    let enc_key = &key[32..64];

    let mut buffer = vec![0u8; data.len() + 16];
    buffer[..data.len()].copy_from_slice(data);
    let ciphertext = Encryptor::<Aes256>::new_from_slices(enc_key, iv)
        .map_err(|error| format!("AES-CBC init error: {}", error))?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|error| format!("AES-CBC encryption error: {}", error))?
        .to_vec();

    // Create HMAC for integrity
    let mut mac =
        HmacSha512::new_from_slice(hmac_key).map_err(|e| format!("HMAC init error: {}", e))?;
    mac.update(&ciphertext);
    let hmac_result = mac.finalize().into_bytes();

    // Combine: IV + HMAC + ciphertext
    // TODO validate it against the XML Encryption spec - is this the correct format?
    let mut result = Vec::with_capacity(iv.len() + hmac_result.len() + ciphertext.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&hmac_result);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data using AES-256-CBC + HMAC-SHA-512
pub fn decrypt_a256cbs_hs512(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 64 {
        return Err("A256CBC-HS512 key must be 64 bytes".to_string());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".to_string());
    }
    if data.len() < 64 {
        return Err("Data too short to contain HMAC".to_string());
    }

    // Extract components
    let hmac_size = 64; // SHA-512 is 64 bytes
    let received_hmac = &data[..hmac_size];
    let ciphertext = &data[hmac_size..];

    // Extract HMAC key and encryption key from the master key
    let hmac_key = &key[..32];
    let enc_key = &key[32..64];

    let mut mac = HmacSha512::new_from_slice(hmac_key)
        .map_err(|error| format!("HMAC init error: {}", error))?;
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)
        .map_err(|_| "HMAC verification failed".to_string())?;

    let mut cipher_buffer = ciphertext.to_vec();
    let plaintext = Decryptor::<Aes256>::new_from_slices(enc_key, iv)
        .map_err(|error| format!("AES-CBC init error: {}", error))?
        .decrypt_padded_mut::<Pkcs7>(&mut cipher_buffer)
        .map_err(|error| format!("AES-CBC decryption error: {}", error))?
        .to_vec();

    Ok(plaintext)
}

/// Generates a random IV for encryption
pub fn generate_iv() -> [u8; 16] {
    let mut rng = rand::rng();
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    iv
}
