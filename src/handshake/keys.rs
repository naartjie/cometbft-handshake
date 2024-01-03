use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;

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

    pub fn public_key(self) -> PublicKey {
        PublicKey {
            verification_key: self.signing_key.verification_key(),
        }
    }

    pub fn sign(self, msg: &[u8]) -> ed25519_consensus::Signature {
        self.signing_key.sign(msg)
    }
}

pub struct PublicKey {
    pub verification_key: VerificationKey,
}
