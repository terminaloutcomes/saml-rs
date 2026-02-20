//! Content encryption for SAML assertions
//!
//! Implements A256CBC-HS512 (AES-256-CBC + HMAC-SHA-512) content encryption
//! as per XML Encryption specification.

use crypto::{
    buffer::{self, BufferResult, ReadBuffer, WriteBuffer},
    mac::Mac as _,
};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha512;
/// HMAC-SHA-512 for integrity checking
type HmacSha512 = Hmac<Sha512>;

/// Encrypts data using AES-256-CBC + HMAC-SHA-512
// loosely based on <https://docs.rs/rust-crypto/latest/src/symmetriccipher/symmetriccipher.rs.html#21-25>
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

    // Encrypt data using AES-256-CBC
    let mut cipher = crypto::aes::cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
        enc_key,
        iv,
        crypto::blockmodes::PkcsPadding,
    );
    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = cipher
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .map_err(|err| format!("{:?}", err))?;

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(write_buffer.take_read_buffer().take_remaining());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    // Create HMAC for integrity
    let mut mac =
        HmacSha512::new_from_slice(hmac_key).map_err(|e| format!("HMAC init error: {}", e))?;
    mac.update(&final_result);
    let hmac_result = mac.finalize().into_bytes();

    // Combine: IV + HMAC + ciphertext
    // TODO validate it against the XML Encryption spec - is this the correct format?
    let mut result = Vec::with_capacity(iv.len() + hmac_result.len() + final_result.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&hmac_result);
    result.extend_from_slice(&final_result);

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

    // Verify HMAC
    let mut mac = crypto::hmac::Hmac::new(crypto::sha2::Sha512::new(), hmac_key);
    mac.input(ciphertext);
    // let expected_hmac = mac.finalize().into_bytes();
    let expected_hmac = mac.result();

    if expected_hmac.code() != received_hmac {
        return Err("HMAC verification failed".to_string());
    }

    // Decrypt using AES-256-CBC
    let mut cipher = crypto::aes::cbc_decryptor(
        crypto::aes::KeySize::KeySize256,
        enc_key,
        iv,
        crypto::blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = cipher
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .map_err(|err| format!("{:?}", err))?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(final_result)
}

/// Generates a random IV for encryption
pub fn generate_iv() -> [u8; 16] {
    let mut rng = rand::rng();
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    iv
}
