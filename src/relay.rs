use crate::{Error, dns::build_lookup_query};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::PathBuf;

pub fn gen_relay_key(_conf_path: &PathBuf) -> Result<(), Error> {
    let key = Aes256Gcm::generate_key(OsRng);
    println!("{}", STANDARD.encode(key));
    Ok(())
}

pub fn encode_for_relay(key: &Key<Aes256Gcm>, dns_message: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, dns_message)
        .expect("encryption failure");

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decode_from_relay(key: &Key<Aes256Gcm>, packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let (nonce_bytes, ciphertext) = packet.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    Aes256Gcm::new(key).decrypt(nonce, ciphertext).ok()
}

pub fn load_key_from_str(key_b64: &str) -> Result<Key<Aes256Gcm>, Error> {
    let bytes = STANDARD
        .decode(key_b64)
        .map_err(|e| Error::Config(format!("invalid RELAY_KEY base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Config(format!(
            "RELAY_KEY must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&bytes))
}
pub async fn resolve_via_relay(
    http: &reqwest::Client,
    worker_url: &str,
    key: &Key<Aes256Gcm>,
    dns_query: &[u8],
) -> Result<Vec<u8>, Error> {
    let encrypted = encode_for_relay(key, dns_query);
    let response = http
        .post(worker_url)
        .body(encrypted)
        .send()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    decode_from_relay(key, &body).ok_or_else(|| Error::Config("decrypt failed".into()))
}

pub async fn resolve_domain_via_relay(
    http: &reqwest::Client,
    worker_url: &str,
    key: &Key<Aes256Gcm>,
    domain: &str,
) -> Result<Vec<u8>, Error> {
    let query = build_lookup_query(domain);

    let encrypted = encode_for_relay(key, &query);
    let response = http
        .post(worker_url)
        .body(encrypted)
        .send()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Config(e.to_string()))?;
    decode_from_relay(key, &body).ok_or_else(|| Error::Config("decrypt failed".into()))
}
