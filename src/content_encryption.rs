//! Content encryption for SAML assertions
//!
//! Implements A256CBC-HS512 (AES-256-CBC + HMAC-SHA-512) content encryption
//! as per XML Encryption specification.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use sha2::Sha512;

use crate::error::SamlError;

/// HMAC-SHA-256 for integrity checking
type HmacSha256 = Hmac<Sha256>;
/// HMAC-SHA-512 for integrity checking
type HmacSha512 = Hmac<Sha512>;

/// Encrypts data using AES-128-CBC + HMAC-SHA-256.
pub fn encrypt_a128cbs_hs256(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 32 {
        return Err(SamlError::InvalidKeyLength(
            "A128CBC-HS256 key must be 32 bytes".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(SamlError::InvalidIvLength(16));
    }

    let hmac_key = &key[..16];
    let enc_key = &key[16..32];

    let mut buffer = vec![0u8; data.len() + 16];
    buffer[..data.len()].copy_from_slice(data);
    let ciphertext = Encryptor::<Aes128>::new_from_slices(enc_key, iv)?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())?
        .to_vec();

    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    mac.update(&ciphertext);
    let hmac_result = mac.finalize().into_bytes();

    let mut result = Vec::with_capacity(iv.len() + hmac_result.len() + ciphertext.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&hmac_result);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypts data using AES-256-CBC + HMAC-SHA-512
pub fn encrypt_a256cbs_hs512(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 64 {
        return Err(SamlError::InvalidKeyLength(
            "A256CBC-HS512 key must be 64 bytes".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(SamlError::InvalidIvLength(16));
    }

    // Extract HMAC key and encryption key from the master key
    let hmac_key = &key[..32];
    let enc_key = &key[32..64];

    let mut buffer = vec![0u8; data.len() + 16];
    buffer[..data.len()].copy_from_slice(data);
    let ciphertext = Encryptor::<Aes256>::new_from_slices(enc_key, iv)?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())?
        .to_vec();

    // Create HMAC for integrity
    let mut mac = HmacSha512::new_from_slice(hmac_key)?;
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

/// Encrypts data using AES-128-GCM.
pub fn encrypt_a128gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 16 {
        return Err(SamlError::InvalidKeyLength(
            "A128GCM key must be 16 bytes".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SamlError::InvalidIvLength(12));
    }

    let cipher = <Aes128Gcm as aes_gcm::aead::KeyInit>::new_from_slice(key).map_err(|error| {
        SamlError::AesCbcEncryption(format!("A128GCM key init error: {}", error))
    })?;
    let nonce_ref = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce_ref, data).map_err(|error| {
        SamlError::AesCbcEncryption(format!("A128GCM encryption error: {}", error))
    })?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Encrypts data using AES-256-GCM.
pub fn encrypt_a256gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 32 {
        return Err(SamlError::InvalidKeyLength(
            "A256GCM key must be 32 bytes".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SamlError::InvalidIvLength(12));
    }

    let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new_from_slice(key).map_err(|error| {
        SamlError::AesCbcEncryption(format!("A256GCM key init error: {}", error))
    })?;
    let nonce_ref = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce_ref, data).map_err(|error| {
        SamlError::AesCbcEncryption(format!("A256GCM encryption error: {}", error))
    })?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data using AES-128-CBC + HMAC-SHA-256.
pub fn decrypt_a128cbs_hs256(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 32 {
        return Err(SamlError::InvalidKeyLength(
            "A128CBC-HS256 key must be 32 bytes".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(SamlError::InvalidIvLength(16));
    }
    if data.len() < 32 {
        return Err(SamlError::InvalidInputLength(
            "Data too short to contain HMAC".to_string(),
        ));
    }

    let hmac_size = 32;
    let received_hmac = &data[..hmac_size];
    let ciphertext = &data[hmac_size..];

    let hmac_key = &key[..16];
    let enc_key = &key[16..32];

    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)?;

    let mut cipher_buffer = ciphertext.to_vec();
    let plaintext = Decryptor::<Aes128>::new_from_slices(enc_key, iv)?
        .decrypt_padded_mut::<Pkcs7>(&mut cipher_buffer)
        .map_err(|error| SamlError::AesCbcEncryption(error.to_string()))?
        .to_vec();

    Ok(plaintext)
}

/// Decrypts data using AES-256-CBC + HMAC-SHA-512
pub fn decrypt_a256cbs_hs512(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 64 {
        return Err(SamlError::InvalidKeyLength(
            "A256CBC-HS512 key must be 64 bytes".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(SamlError::InvalidIvLength(16));
    }
    if data.len() < 64 {
        return Err(SamlError::InvalidInputLength(
            "Data too short to contain HMAC".to_string(),
        ));
    }

    // Extract components
    let hmac_size = 64; // SHA-512 is 64 bytes
    let received_hmac = &data[..hmac_size];
    let ciphertext = &data[hmac_size..];

    // Extract HMAC key and encryption key from the master key
    let hmac_key = &key[..32];
    let enc_key = &key[32..64];

    let mut mac = HmacSha512::new_from_slice(hmac_key)
        .map_err(|error| SamlError::Other(format!("HMAC init error: {}", error)))?;
    mac.update(ciphertext);
    mac.verify_slice(received_hmac)?;

    let mut cipher_buffer = ciphertext.to_vec();
    let plaintext = Decryptor::<Aes256>::new_from_slices(enc_key, iv)?
        .decrypt_padded_mut::<Pkcs7>(&mut cipher_buffer)?
        .to_vec();

    Ok(plaintext)
}

/// Decrypts data using AES-128-GCM.
pub fn decrypt_a128gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 16 {
        return Err(SamlError::InvalidKeyLength(
            "A128GCM key must be 16 bytes".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SamlError::InvalidIvLength(12));
    }

    let cipher = <Aes128Gcm as aes_gcm::aead::KeyInit>::new_from_slice(key)
        .map_err(|error| SamlError::Other(format!("A128GCM key init error: {}", error)))?;
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_ref, data)
        .map_err(|error| SamlError::Other(format!("A128GCM decryption error: {}", error)))
}

/// Decrypts data using AES-256-GCM.
pub fn decrypt_a256gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SamlError> {
    if key.len() != 32 {
        return Err(SamlError::InvalidKeyLength(
            "A256GCM key must be 32 bytes".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SamlError::InvalidIvLength(12));
    }

    let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new_from_slice(key)
        .map_err(|error| SamlError::Other(format!("A256GCM key init error: {}", error)))?;
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_ref, data)
        .map_err(|error| SamlError::Other(format!("A256GCM decryption error: {}", error)))
}

/// Generates a random IV for encryption
pub fn generate_iv() -> [u8; 16] {
    let mut rng = rand::rng();
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    iv
}

/// Generates a random 12-byte nonce for GCM encryption.
pub fn generate_gcm_nonce() -> [u8; 12] {
    let mut rng = rand::rng();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    nonce
}
