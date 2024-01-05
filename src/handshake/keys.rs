use ed25519_consensus::{SigningKey, VerificationKey};
use sha2::{digest::Digest, Sha256};

use std::fmt;
use std::fmt::{Display, Write};

#[derive(Clone)]
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    pub fn generate() -> Self {
        let signing_key = ed25519_consensus::SigningKey::new(rand_core::OsRng);
        Self(signing_key)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verification_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

#[derive(Clone)]
pub struct PublicKey(VerificationKey);

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

impl From<VerificationKey> for PublicKey {
    fn from(verification_key: ed25519_consensus::VerificationKey) -> Self {
        PublicKey(verification_key)
    }
}

impl Display for PublicKey {
    /// hex encoded string - 40 chars long
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digest = Sha256::digest(self.0.as_bytes());
        write!(f, "{}", hex_string(digest[..20].to_vec()))
    }
}

/// Converts Vec<u8> into a hex encoded string
pub fn hex_string(bytes: Vec<u8>) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            write!(&mut acc, "{byte:02x}").unwrap();
            acc
        })
}
