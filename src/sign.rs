//! Functions for signing data
//!
//! Here be crypto-dragons.
//!

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

// use std::io;
use openssl::pkey::Private;
use std::fs::File;
use std::io::prelude::*;
pub fn load_key_from_filename(key_filename: &str) -> Result<PKey<Private>, String> {
    let mut f = match File::open(key_filename) {
        Ok(value) => value,
        Err(error) => return Err(format!("Error loading file {}: {:?}", &key_filename, error)),
    };
    let mut pkey_buffer = Vec::new();
    // read the whole file
    // TODO: handle file read errors, but if we've gotten here without bailing then well, eek?
    match f.read_to_end(&mut pkey_buffer) {
        Ok(_) => eprintln!("Read private key OK"),
        Err(error) => {
            return Err(format!("Failed to read private key? {:?}", error));
        }
    }

    debug!("key:  {}", key_filename);
    let keypair = match Rsa::private_key_from_pem(&pkey_buffer) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!("Failed to load pkey from pem bytes: {:?}", error));
        }
    };
    // let keypair = Rsa::generate(2048).unwrap();
    match PKey::from_rsa(keypair) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!("Failed to convert into PKey object: {:?}", error)),
    }
}

use openssl::x509::X509;

pub fn load_public_cert_from_filename(cert_filename: &str) -> Result<X509, String> {
    log::debug!("loading cert:  {}", cert_filename);

    let mut f = match File::open(&cert_filename) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!(
                "Error loading certificate file {}: {:?}",
                &cert_filename, error
            ))
        }
    };

    let mut cert_buffer = Vec::new();
    // read the whole file
    // TODO: handle file read errors, but if we've gotten here without bailing then well, how'd the server start up?
    match f.read_to_end(&mut cert_buffer) {
        Ok(_) => eprintln!("Read certificate OK"),
        Err(error) => {
            return Err(format!("Failed to read cert? {:?}", error));
        }
    }

    match openssl::x509::X509::from_pem(&cert_buffer) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!(
            "Failed to load certificate from pem bytes: {:?}",
            error
        )),
    }
}

// TODO add some testing
pub fn sign_data(cert_filename: String, key_filename: String, bytes_to_sign: &[u8]) {
    // Generate a keypair
    debug!("cert: {}", cert_filename);

    // let data = b"hello, world!";
    // let data2 = b"hola, mundo!";
    let keypair: PKey<Private> = match load_key_from_filename(&key_filename) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "Failed to load private key from {}: {:?}",
                &key_filename, error
            );
            return;
        }
    };

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
