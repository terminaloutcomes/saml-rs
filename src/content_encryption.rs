//! Content encryption for SAML assertions
//!
//! Implements CBC+HMAC and GCM content encryption helpers used by encrypted
//! assertion handling.
//!
//! For CBC+HMAC modes, construction follows AES_CBC_HMAC_SHA2 semantics from
//! RFC 7518, serialized into a single packed payload suitable for
//! `xenc:CipherValue` transport.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use sha2::Sha512;
use subtle::ConstantTimeEq;

use crate::error::SamlError;

/// HMAC-SHA-256 for integrity checking
type HmacSha256 = Hmac<Sha256>;
/// HMAC-SHA-512 for integrity checking
type HmacSha512 = Hmac<Sha512>;

/// Packed payload format for CBC+HMAC modes.
///
/// This implementation follows the AES_CBC_HMAC_SHA2 construction semantics
/// (RFC 7518 §5.2, with empty AAD) while storing all fields in one blob for
/// XML `xenc:CipherValue` transport:
///
/// - outer framing: `IV || CIPHERTEXT || TAG`
/// - `TAG` is the left-most half of the HMAC output
///   - A128CBC-HS256 => 16 bytes
///   - A256CBC-HS512 => 32 bytes
/// - MAC input: `IV || CIPHERTEXT || AL`, where `AL` is the 64-bit big-endian
///   AAD bit length (always 0 in this implementation because AAD is empty).
///
/// References:
/// - RFC 7518 §5.2 (AES_CBC_HMAC_SHA2)
/// - RFC 7516 Appendix B (worked examples of tag truncation)
// TODO take the worked examples from RFC7516 and implement them as tests to verify interoperability and correctness of this implementation.
const AAD_LENGTH_BYTES_FOR_EMPTY_AAD: [u8; 8] = 0u64.to_be_bytes();

fn cbc_hmac_input(iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(iv.len() + ciphertext.len() + 8);
    input.extend_from_slice(iv);
    input.extend_from_slice(ciphertext);
    input.extend_from_slice(&AAD_LENGTH_BYTES_FOR_EMPTY_AAD);
    input
}

/// Encrypts data using AES-128-CBC + HMAC-SHA-256.
pub fn encrypt_a128cbc_hs256(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SamlError> {
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
    let mac_input = cbc_hmac_input(iv, &ciphertext);
    mac.update(&mac_input);
    let hmac_result = mac.finalize().into_bytes();
    let tag = &hmac_result[..16];

    let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(tag);

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

    // Create HMAC for integrity/authentication and truncate to 32-byte tag.
    let mut mac = HmacSha512::new_from_slice(hmac_key)?;
    let mac_input = cbc_hmac_input(iv, &ciphertext);
    mac.update(&mac_input);
    let hmac_result = mac.finalize().into_bytes();
    let tag = &hmac_result[..32];

    // Combine packed payload as IV + ciphertext + tag.
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(tag);

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
    if data.len() < 16 {
        return Err(SamlError::InvalidInputLength(
            "Data too short to contain authentication tag".to_string(),
        ));
    }

    let tag_size = 16;
    let split_index = data.len() - tag_size;
    let ciphertext = &data[..split_index];
    let received_tag = &data[split_index..];

    let hmac_key = &key[..16];
    let enc_key = &key[16..32];

    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    let mac_input = cbc_hmac_input(iv, ciphertext);
    mac.update(&mac_input);
    let computed_hmac = mac.finalize().into_bytes();
    let computed_tag = &computed_hmac[..16];
    if !bool::from(computed_tag.ct_eq(received_tag)) {
        return Err(SamlError::Other(
            "HMAC authentication tag mismatch".to_string(),
        ));
    }

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
    if data.len() < 32 {
        return Err(SamlError::InvalidInputLength(
            "Data too short to contain authentication tag".to_string(),
        ));
    }

    // Extract components
    let tag_size = 32; // Left-most half of SHA-512 output
    let split_index = data.len() - tag_size;
    let ciphertext = &data[..split_index];
    let received_tag = &data[split_index..];

    // Extract HMAC key and encryption key from the master key
    let hmac_key = &key[..32];
    let enc_key = &key[32..64];

    let mut mac = HmacSha512::new_from_slice(hmac_key)?;
    let mac_input = cbc_hmac_input(iv, ciphertext);
    mac.update(&mac_input);
    let computed_hmac = mac.finalize().into_bytes();
    let computed_tag = &computed_hmac[..32];
    if !bool::from(computed_tag.ct_eq(received_tag)) {
        return Err(SamlError::Other(
            "HMAC authentication tag mismatch".to_string(),
        ));
    }

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
