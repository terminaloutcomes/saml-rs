//! Functions for signing data
//!
//! Here be crypto-dragons.
//!

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

// use std::io;
use std::fs::File;
use std::io::prelude::*;

// TODO add some testing
pub fn sign_data(cert_filename: String, key_filename: String, bytes_to_sign: &[u8]) {
    // Generate a keypair

    let mut f = match File::open(&key_filename) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Error loading file {}: {:?}", &key_filename, error);
            return;
        }
    };
    let mut pkey_buffer = Vec::new();
    // read the whole file
    // TODO: handle file read errors, but if we've gotten here without bailing then well, eek?
    match f.read_to_end(&mut pkey_buffer) {
        Ok(_) => eprintln!("Read private key OK"),
        Err(error) => {
            eprintln!("Failed to read private key? {:?}", error);
            return;
        }
    }

    debug!("cert: {}", cert_filename);
    debug!("key:  {}", key_filename);
    let keypair = match Rsa::private_key_from_pem(&pkey_buffer) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Failed to load pkey from pem bytes: {:?}", error);
            return;
        }
    };
    // let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    // let data = b"hello, world!";
    // let data2 = b"hola, mundo!";

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(bytes_to_sign).unwrap();

    let signature = signer.sign_to_vec().unwrap();

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
    verifier.update(bytes_to_sign).unwrap();
    // verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
    eprintln!("Signed things, maybe?");
}
