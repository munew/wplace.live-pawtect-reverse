use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::error::Error;
use aead::AeadCore;
use aead::Nonce;
use crate::utils::sha256;

mod utils;

const KEY: [u8; 32] = [19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55];

pub fn encrypt_token(data: &[u8]) -> Result<String, Box<dyn Error>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&KEY)?;
    let nonce = XChaCha20Poly1305::generate_nonce().unwrap();

    let ciphertext = cipher.encrypt(&nonce, data)?;
    Ok(format!("{}.{}", base64::prelude::BASE64_STANDARD.encode(ciphertext), base64::prelude::BASE64_STANDARD.encode(nonce.0)))
}

pub fn decrypt_token(token: String) -> Result<Vec<u8>, Box<dyn Error>> {
    let split = token.split(".").collect::<Vec<&str>>();
    if split.len() != 2 {
        return Err("wrong format".into());
    }

    let ciphertext = split.get(0).unwrap();
    let nonce = split.get(1).unwrap();

    let decoded_ciphertext = base64::prelude::BASE64_STANDARD.decode(ciphertext.as_bytes())?;
    let decoded_nonce: [u8; 24] = base64::prelude::BASE64_STANDARD.decode(nonce.as_bytes())?.try_into().unwrap();

    let cipher = XChaCha20Poly1305::new_from_slice(&KEY)?;
    let nonce = Nonce::<XChaCha20Poly1305>::from_slice(&decoded_nonce);
    let plaintext = cipher.decrypt(&nonce, decoded_ciphertext.as_ref())?;

    Ok(plaintext)
}

pub fn sign(hosts: &[String], body: Vec<u8>) -> Result<String, Box<dyn Error>> {
    let mut plaintext = Vec::with_capacity(128);

    // At first glance I thought first 4 bytes were timestamp, but it never changes and points to November 2025
    // so yeah no idea what's this nor what's the 0
    plaintext.extend_from_slice(&[105, 19, 131, 172, 0]);
    // body sha256
    plaintext.extend_from_slice(sha256(body.as_slice())?.as_slice());

    plaintext.extend_from_slice(&[0, 0, hosts.len() as u8]);
    for host in hosts {
        let hosts_len: u32 = host.len() as u32;
        plaintext.extend(hosts_len.to_le_bytes());
        plaintext.extend_from_slice(host.as_bytes());
    }

    encrypt_token(plaintext.as_slice())
}