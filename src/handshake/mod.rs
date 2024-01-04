use std::io::Error;
use std::slice;

use merlin::Transcript;
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    net::TcpStream,
};

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use curve25519_dalek_ng::{
    constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
};
use tendermint_proto::v0_38 as proto;

use kdf::Kdf;
use keys::PrivateKey;
use nonce::Nonce;

use self::keys::PublicKey;

mod codecs;
mod kdf;
mod keys;
mod nonce;
mod wire_encryption;

async fn share_auth_signature(
    secure_connection: &mut SecureConnection,
    local_private_key: &PrivateKey,
) -> Result<proto::p2p::AuthSigMessage, std::io::Error> {
    // 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
    const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

    let local_signature = local_private_key.sign(&secure_connection.sc_mac);

    let auth_signature = codecs::encode_auth_signature(
        &local_private_key.public_key().verification_key,
        &local_signature,
    );

    let mut send_nonce = Nonce::default();

    let _size = wire_encryption::encrypt_and_write(
        &mut secure_connection.write_stream,
        &mut send_nonce,
        &secure_connection.send_cipher,
        &auth_signature,
    )
    .await?;

    let mut buf = vec![0; AUTH_SIG_MSG_RESPONSE_LEN];

    let mut recv_nonce = Nonce::default();
    let _size = wire_encryption::read_and_decrypt(
        &mut secure_connection.read_stream,
        &mut recv_nonce,
        &secure_connection.recv_cipher,
        &mut buf,
    )
    .await?;

    codecs::decode_auth_signature(&buf)
}

pub fn authenticate_remote_pubkey(
    auth_sig_msg: proto::p2p::AuthSigMessage,
    sc_mac: [u8; 32],
) -> Result<PublicKey, std::io::Error> {
    let to_err = |e| Error::other(format!("signature error: {:?}", e));

    let pk_sum = auth_sig_msg.pub_key.and_then(|key| key.sum);
    let pk_sum = pk_sum.expect("missing key");

    let remote_pubkey = match pk_sum {
        proto::crypto::public_key::Sum::Ed25519(ref bytes) => {
            ed25519_consensus::VerificationKey::try_from(&bytes[..]).map_err(to_err)
        }
        proto::crypto::public_key::Sum::Secp256k1(_) => Err(Error::other("unsupported key")),
    }?;

    let remote_sig =
        ed25519_consensus::Signature::try_from(auth_sig_msg.sig.as_slice()).map_err(to_err)?;

    remote_pubkey.verify(&remote_sig, &sc_mac).map_err(to_err)?;

    Ok(remote_pubkey.into())
}

async fn send_our_eph_pubkey(
    stream: &mut OwnedWriteHalf,
    local_eph_pubkey: &MontgomeryPoint,
) -> Result<(), std::io::Error> {
    stream
        .write_all(&codecs::encode_our_eph_pubkey(local_eph_pubkey))
        .await?;

    Ok(())
}

async fn receive_their_eph_pubkey(
    stream: &mut OwnedReadHalf,
) -> Result<MontgomeryPoint, std::io::Error> {
    let mut response_len = 0_u8;
    stream
        .read_exact(slice::from_mut(&mut response_len))
        .await?;
    let mut buf = vec![0; response_len as usize];
    stream.read_exact(&mut buf).await?;
    let remote_eph_pubkey = codecs::decode_remote_eph_pubkey(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("oh noes {}", e)))?;

    Ok(remote_eph_pubkey)
}

struct SecureConnection {
    read_stream: OwnedReadHalf,
    write_stream: OwnedWriteHalf,
    sc_mac: [u8; 32],
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
}

impl SecureConnection {
    pub fn new(
        read_stream: OwnedReadHalf,
        write_stream: OwnedWriteHalf,
        local_eph_privkey: &Scalar,
        remote_eph_pubkey: &MontgomeryPoint,
    ) -> Result<SecureConnection, std::io::Error> {
        fn sort32(first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
            if second > first {
                (first, second)
            } else {
                (second, first)
            }
        }

        let local_eph_pubkey = X25519_BASEPOINT * local_eph_privkey;
        let shared_secret = local_eph_privkey * remote_eph_pubkey;

        // Reject all-zero outputs from X25519 (i.e. from low-order points)
        // - https://github.com/tendermint/kms/issues/142
        // - https://eprint.iacr.org/2019/526.pdf
        if shared_secret.as_bytes().ct_eq(&[0x00; 32]).unwrap_u8() == 1 {
            return Err(Error::other("low order key"));
        }

        // Sort by lexical order.
        let local_eph_pubkey_bytes = *local_eph_pubkey.as_bytes();
        let (low_eph_pubkey_bytes, high_eph_pubkey_bytes) =
            sort32(local_eph_pubkey_bytes, *remote_eph_pubkey.as_bytes());

        let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");
        transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", &low_eph_pubkey_bytes);
        transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", &high_eph_pubkey_bytes);
        transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

        // Check if the local ephemeral public key was the least, lexicographically sorted.
        let loc_is_least = local_eph_pubkey_bytes == low_eph_pubkey_bytes;

        let kdf = Kdf::derive_secrets_and_challenge(shared_secret.as_bytes(), loc_is_least);

        let mut sc_mac: [u8; 32] = [0; 32];

        transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut sc_mac);

        Ok(SecureConnection {
            read_stream,
            write_stream,
            sc_mac,
            send_cipher: ChaCha20Poly1305::new(&kdf.send_secret.into()),
            recv_cipher: ChaCha20Poly1305::new(&kdf.recv_secret.into()),
        })
    }
}

// impl SecureConnection {
//     async fn read(&mut self, buf: &mut [u8]) -> Result<(), io::Error> {
//         let _size = self.read_stream.read_exact(buf).await?;
//         Ok(())
//     }

//     async fn write(&mut self, src: &[u8]) -> Result<(), io::Error> {
//         self.write_stream.write_all(src).await?;
//         Ok(())
//     }
// }

pub async fn do_handshake(stream: TcpStream) -> Result<(), std::io::Error> {
    let local_private_key = PrivateKey::generate();

    let local_eph_privkey = Scalar::random(&mut OsRng);
    let local_eph_pubkey = X25519_BASEPOINT * local_eph_privkey;

    // send and receive eph pubkeys in parallel
    let (mut read_stream, mut write_stream) = stream.into_split();
    let (_, remote_eph_pubkey) = tokio::join!(
        send_our_eph_pubkey(&mut write_stream, &local_eph_pubkey),
        receive_their_eph_pubkey(&mut read_stream),
    );

    let remote_eph_pubkey = remote_eph_pubkey?;

    let mut secure_connection = SecureConnection::new(
        read_stream,
        write_stream,
        &local_eph_privkey,
        &remote_eph_pubkey,
    )?;

    let auth_sig_msg = share_auth_signature(&mut secure_connection, &local_private_key).await?;

    let remote_pubkey = authenticate_remote_pubkey(auth_sig_msg, secure_connection.sc_mac)?;

    println!(
        "\nPeer handshake authorized\n    this node = {}\n  remote node = {}",
        local_private_key.public_key(),
        remote_pubkey,
    );

    Ok(())
}
