use chacha20poly1305::{
    ChaCha20Poly1305, Key,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use rand::RngExt;
use serde::Deserialize;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const LEN_PREFIX: usize = 2;
pub const TAG_LEN: usize = 16; // Poly1305 tag, appended by `encrypt()`
pub const PAD_MIN: usize = 32;
pub const PAD_MAX: usize = 192;

#[derive(Clone)]
pub struct ObfsKey(ChaCha20Poly1305);

#[derive(Debug)]
pub enum ObfsError {
    BadKey,
}

impl ObfsKey {
    pub fn from_bytes(key: &[u8; KEY_LEN]) -> Self {
        Self(ChaCha20Poly1305::new(Key::from_slice(key)))
    }

    pub fn from_base64(s: &str) -> Result<Self, ObfsError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(s).map_err(|_| ObfsError::BadKey)?;
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| ObfsError::BadKey)?;
        Ok(Self::from_bytes(&arr))
    }

    /// Generates a fresh random key and returns it base64-encoded, for CLI keygen use.
    pub fn generate_base64() -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key: [u8; KEY_LEN] = rand::rng().random();
        STANDARD.encode(key)
    }

    fn random_padding(len: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        (0..len).map(|_| rng.random()).collect()
    }

    /// Wraps a real DNS query into an obfuscated datagram. Every call uses a
    /// fresh nonce and a randomized padding length, so no two packets — even
    /// for the same query — look alike or share a fixed size.
    pub fn encode(&self, query: &[u8]) -> Vec<u8> {
        let mut rng = rand::rng();
        let span = (PAD_MAX - PAD_MIN + 1) as u16;
        let pad_len = PAD_MIN + (rng.random::<u16>() % span) as usize;

        let mut plaintext = Vec::with_capacity(LEN_PREFIX + query.len() + pad_len);
        plaintext.extend_from_slice(&(query.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(query);
        plaintext.extend_from_slice(&Self::random_padding(pad_len));

        let nonce_bytes: [u8; NONCE_LEN] = rng.random();
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // ChaCha20Poly1305::encrypt only fails on buffer/param misuse, not on
        // untrusted input — we control both key and nonce length here.
        let ciphertext = self
            .0
            .encrypt(nonce, plaintext.as_ref())
            .expect("obfs encryption failure");

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Unwraps an obfuscated datagram back into the real DNS query bytes.
    /// Returns `None` on anything malformed, forged, or encrypted under a
    /// different key — callers MUST drop silently on `None`, never reply,
    /// so active probing gets nothing to fingerprint.
    pub fn decode(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < NONCE_LEN + TAG_LEN + LEN_PREFIX {
            return None;
        }
        let (nonce_bytes, ciphertext) = datagram.split_at(NONCE_LEN);
        let nonce = GenericArray::from_slice(nonce_bytes);

        let plaintext = self.0.decrypt(nonce, ciphertext).ok()?;
        if plaintext.len() < LEN_PREFIX {
            return None;
        }
        let len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if LEN_PREFIX + len > plaintext.len() {
            return None; // length prefix lies about its own payload — reject
        }
        Some(plaintext[LEN_PREFIX..LEN_PREFIX + len].to_vec())
    }
}
