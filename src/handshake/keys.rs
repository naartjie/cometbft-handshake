use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;
use sha2::{digest::Digest, Sha256};

use std::fmt;
use std::fmt::{Display, Write};

#[derive(Clone)]
pub struct PrivateKey {
    signing_key: SigningKey,
}

impl PrivateKey {
    pub fn generate() -> Self {
        let csprng = OsRng {};
        let signing_key = ed25519_consensus::SigningKey::new(csprng);

        Self { signing_key }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verification_key: self.signing_key.verification_key(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> ed25519_consensus::Signature {
        self.signing_key.sign(msg)
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pub verification_key: VerificationKey,
}

impl From<VerificationKey> for PublicKey {
    fn from(vk: ed25519_consensus::VerificationKey) -> Self {
        PublicKey {
            verification_key: vk,
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digest = Sha256::digest(self.verification_key.as_bytes());
        write!(f, "{}", hex_string(digest[..20].to_vec()))
    }
}

pub fn hex_string(bytes: Vec<u8>) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            write!(&mut acc, "{byte:02x}").unwrap();
            acc
        })
}
