use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use curve25519_dalek_ng::{
    constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
};

pub struct PrivateKey {
    signing_key: SigningKey,
}

pub struct PublicKey {
    verification_key: VerificationKey,
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
}

pub fn encode_initial_handshake(eph_pubkey: &MontgomeryPoint) -> Vec<u8> {
    // go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L307-L312
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x22, 0x0a, 0x20]);
    buf.extend_from_slice(eph_pubkey.as_bytes());
    buf
}

pub fn handshake_start(stream: TcpStream, private_key: PrivateKey) -> Result<(), String> {
    let private_key = PrivateKey::generate();
    let local_eph_privkey = Scalar::random(&mut OsRng);
    let local_eph_pubkey = X25519_BASEPOINT * &local_eph_privkey;

    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "127.0.0.1:26656";
    let mut stream = TcpStream::connect(addr).await?;

    println!("connection to peer opened on {}", addr);

    let result = stream.write(b"hello world\n").await;
    println!("wrote to stream; success={:?}", result.is_ok());

    Ok(())
}
