use std::io::Error;
use std::slice;

use ed25519_consensus::VerificationKey;
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
use prost::Message as _;
use tendermint_proto::v0_38 as proto;

use kdf::Kdf;
use keys::PrivateKey;
use nonce::Nonce;
mod kdf;
mod keys;
mod nonce;
mod wire_encryption;

pub fn decode_remote_eph_pubkey(bytes: &[u8]) -> Result<MontgomeryPoint, std::io::Error> {
    // go implementation
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L315-L323
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err(Error::other("malformed_handshake"));
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");

    Ok(MontgomeryPoint(eph_pubkey_bytes))
}

pub fn got_key(
    private_key: &PrivateKey,
    local_eph_privkey: &Scalar,
    remote_eph_pubkey: &MontgomeryPoint,
) -> Result<
    (
        ed25519_consensus::Signature,
        [u8; 32],
        ChaCha20Poly1305,
        ChaCha20Poly1305,
    ),
    std::io::Error,
> {
    fn sort32(first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        if second > first {
            (first, second)
        } else {
            (second, first)
        }
    }

    let local_eph_pubkey = X25519_BASEPOINT * local_eph_privkey;

    // Compute common shared secret.
    let shared_secret = local_eph_privkey * remote_eph_pubkey;

    let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

    // Reject all-zero outputs from X25519 (i.e. from low-order points)
    //
    // See the following for information on potential attacks this check
    // aids in mitigating:
    //
    // - https://github.com/tendermint/kms/issues/142
    // - https://eprint.iacr.org/2019/526.pdf
    if shared_secret.as_bytes().ct_eq(&[0x00; 32]).unwrap_u8() == 1 {
        return Err(Error::other("low order key"));
    }

    // Sort by lexical order.
    let local_eph_pubkey_bytes = *local_eph_pubkey.as_bytes();
    let (low_eph_pubkey_bytes, high_eph_pubkey_bytes) =
        sort32(local_eph_pubkey_bytes, *remote_eph_pubkey.as_bytes());

    transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", &low_eph_pubkey_bytes);
    transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", &high_eph_pubkey_bytes);
    transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

    // Check if the local ephemeral public key was the least, lexicographically sorted.
    let loc_is_least = local_eph_pubkey_bytes == low_eph_pubkey_bytes;

    let kdf = Kdf::derive_secrets_and_challenge(shared_secret.as_bytes(), loc_is_least);

    let mut sc_mac: [u8; 32] = [0; 32];

    transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut sc_mac);

    // Sign the challenge bytes for authentication.
    let local_signature = private_key.clone().sign(&sc_mac);

    // Ok((
    //     sc_mac,
    //     ChaCha20Poly1305::new(&kdf.recv_secret.into()),
    //     ChaCha20Poly1305::new(&kdf.send_secret.into()),
    //     kdf,
    //     local_signature,
    // ));

    Ok((
        local_signature,
        sc_mac,
        ChaCha20Poly1305::new(&kdf.recv_secret.into()),
        ChaCha20Poly1305::new(&kdf.send_secret.into()),
    ))
}

pub fn encode_auth_signature(
    pub_key: &ed25519_consensus::VerificationKey,
    signature: &ed25519_consensus::Signature,
) -> Vec<u8> {
    // Protobuf `AuthSigMessage`
    let pub_key = proto::crypto::PublicKey {
        sum: Some(proto::crypto::public_key::Sum::Ed25519(
            pub_key.as_ref().to_vec(),
        )),
    };

    let msg = proto::p2p::AuthSigMessage {
        pub_key: Some(pub_key),
        sig: signature.to_bytes().to_vec(),
    };

    let mut buf = Vec::new();
    msg.encode_length_delimited(&mut buf)
        .expect("couldn't encode AuthSigMessage proto");
    buf
}

pub fn decode_auth_signature(bytes: &[u8]) -> Result<proto::p2p::AuthSigMessage, std::io::Error> {
    proto::p2p::AuthSigMessage::decode_length_delimited(bytes)
        .map_err(|e| Error::other(e.to_string()))
}

pub async fn share_auth_signature(
    read_stream: &mut OwnedReadHalf,
    write_stream: &mut OwnedWriteHalf,
    local_private_key: &PrivateKey,
    local_signature: &ed25519_consensus::Signature,
    recv_cipher: &ChaCha20Poly1305,
    send_cipher: &ChaCha20Poly1305,
) -> Result<proto::p2p::AuthSigMessage, std::io::Error> {
    // 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
    const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

    let buf = encode_auth_signature(
        &local_private_key.clone().public_key().verification_key,
        local_signature,
    );

    let mut send_nonce = Nonce::default();

    let _size =
        wire_encryption::encrypt_and_write(write_stream, &mut send_nonce, send_cipher, &buf)
            .await?;
    // stream.write_all(&buf).await?;

    let mut buf = vec![0; AUTH_SIG_MSG_RESPONSE_LEN];

    let mut recv_nonce = Nonce::default();
    let _size =
        wire_encryption::read_and_decrypt(read_stream, &mut recv_nonce, recv_cipher, &mut buf)
            .await?;
    // stream.read_exact(&mut buf).await?;

    decode_auth_signature(&buf)
}

pub fn got_signature(
    auth_sig_msg: proto::p2p::AuthSigMessage,
    sc_mac: [u8; 32],
) -> Result<VerificationKey, std::io::Error> {
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

    Ok(remote_pubkey)
}

fn encode_our_eph_pubkey(eph_pubkey: &MontgomeryPoint) -> Vec<u8> {
    // go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L307-L312
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x22, 0x0a, 0x20]);
    buf.extend_from_slice(eph_pubkey.as_bytes());
    buf
}

async fn send_our_eph_pubkey(
    stream: &mut OwnedWriteHalf,
    local_eph_pubkey: &MontgomeryPoint,
) -> Result<(), std::io::Error> {
    stream
        .write_all(&encode_our_eph_pubkey(local_eph_pubkey))
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
    let remote_eph_pubkey = decode_remote_eph_pubkey(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("oh noes {}", e)))?;

    Ok(remote_eph_pubkey)
}

pub async fn do_handshake(stream: TcpStream) -> Result<(), std::io::Error> {
    let private_key = PrivateKey::generate();
    let local_eph_privkey = Scalar::random(&mut OsRng);
    let local_eph_pubkey = X25519_BASEPOINT * local_eph_privkey;

    let (mut read_half, mut write_half) = stream.into_split();

    // send and receive eph pubkeys in parallel
    let (_, remote_eph_pubkey) = tokio::join!(
        send_our_eph_pubkey(&mut write_half, &local_eph_pubkey),
        receive_their_eph_pubkey(&mut read_half),
    );

    let remote_eph_pubkey = remote_eph_pubkey?;

    let (local_signature, sc_mac, recv_cipher, send_cipher) =
        got_key(&private_key, &local_eph_privkey, &remote_eph_pubkey)?;

    // Share each other's pubkey & challenge signature.
    // NOTE: the data must be encrypted/decrypted using ciphers.
    // let verification_key = private_key.public_key().verification_key;
    let auth_sig_msg = share_auth_signature(
        &mut read_half,
        &mut write_half,
        &private_key,
        &local_signature,
        &recv_cipher,
        &send_cipher,
    )
    .await?;

    // Authenticate remote pubkey.
    let remote_pubkey = got_signature(auth_sig_msg, sc_mac)?;

    println!("We've authorized {:?}", remote_pubkey);

    Ok(())
}
