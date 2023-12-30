use std::{error::Error, slice};

use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub fn decode_initial_handshake(bytes: &[u8]) -> Result<MontgomeryPoint, &str> {
    // go implementation
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L315-L323
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err("malformed_handshake");
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");

    Ok(MontgomeryPoint(eph_pubkey_bytes))
}

pub async fn handshake_start(
    stream: &mut TcpStream,
    private_key: PrivateKey,
) -> Result<(), std::io::Error> {
    let private_key = PrivateKey::generate();
    let local_eph_privkey = Scalar::random(&mut OsRng);
    let local_eph_pubkey = X25519_BASEPOINT * &local_eph_privkey;

    stream.write_all(&encode_initial_handshake(&local_eph_pubkey));

    let mut response_len = 0_u8;
    stream
        .read_exact(slice::from_mut(&mut response_len))
        .await?;

    let mut buf = vec![0; response_len as usize];
    stream.read_exact(&mut buf).await?;

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
