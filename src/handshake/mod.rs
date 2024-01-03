use std::io;
use std::io::Read;
use std::{cmp, error::Error, slice};

use ed25519_consensus::{SigningKey, VerificationKey};
use merlin::Transcript;
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use prost::Message as _;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use curve25519_dalek_ng::{
    constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
};
use tendermint_proto::v0_38 as proto;

use nonce::{Nonce, SIZE as NONCE_SIZE};

use kdf::Kdf;

mod kdf;

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
    verification_key: VerificationKey,
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

pub fn sort32(first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if second > first {
        (first, second)
    } else {
        (second, first)
    }
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
    Box<dyn Error>,
> {
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
        return Err("low order key".into());
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

pub fn decode_auth_signature(bytes: &[u8]) -> Result<proto::p2p::AuthSigMessage, Box<dyn Error>> {
    proto::p2p::AuthSigMessage::decode_length_delimited(bytes).map_err(|e| e.to_string().into())
}

pub async fn share_auth_signature(
    stream: &mut TcpStream,
    local_private_key: &PrivateKey,
    local_signature: &ed25519_consensus::Signature,
    recv_cipher: &ChaCha20Poly1305,
    send_cipher: &ChaCha20Poly1305,
) -> Result<proto::p2p::AuthSigMessage, Box<dyn Error>> {
    // 32 + 64 + (proto overhead = 1 prefix + 2 fields + 2 lengths + total length)
    const AUTH_SIG_MSG_RESPONSE_LEN: usize = 103;

    let buf = encode_auth_signature(
        &local_private_key.clone().public_key().verification_key,
        local_signature,
    );

    let mut send_nonce = Nonce::default();

    let _size = encrypt_and_write(stream, &mut send_nonce, send_cipher, &buf).await?;
    // stream.write_all(&buf).await?;

    let mut buf = vec![0; AUTH_SIG_MSG_RESPONSE_LEN];

    let mut recv_nonce = Nonce::default();
    let _size = read_and_decrypt(stream, &mut recv_nonce, recv_cipher, &mut buf).await?;
    // stream.read_exact(&mut buf).await?;

    decode_auth_signature(&buf)
}

pub fn got_signature(
    auth_sig_msg: proto::p2p::AuthSigMessage,
    sc_mac: [u8; 32],
) -> Result<VerificationKey, Box<dyn Error>> {
    let pk_sum = auth_sig_msg.pub_key.and_then(|key| key.sum);
    let pk_sum = pk_sum.expect("missing key");

    let remote_pubkey = match pk_sum {
        proto::crypto::public_key::Sum::Ed25519(ref bytes) => {
            ed25519_consensus::VerificationKey::try_from(&bytes[..]).map_err(|_| "signature error")
        }
        proto::crypto::public_key::Sum::Secp256k1(_) => Err("unsupported key"),
    }?;

    let remote_sig = ed25519_consensus::Signature::try_from(auth_sig_msg.sig.as_slice())
        .map_err(|_| "signature error")?;

    remote_pubkey
        .verify(&remote_sig, &sc_mac)
        .map_err(|_| "signature error")?;

    // We've authorized.
    Ok(remote_pubkey)
}

pub const TAG_SIZE: usize = 16;
pub const DATA_MAX_SIZE: usize = 1024;
/// 4 + 1024 == 1028 total frame size
const DATA_LEN_SIZE: usize = 4;
const TOTAL_FRAME_SIZE: usize = DATA_MAX_SIZE + DATA_LEN_SIZE;

mod nonce;

/// Decrypt AEAD authenticated data
fn decrypt(
    ciphertext: &[u8],
    recv_cipher: &ChaCha20Poly1305,
    recv_nonce: &Nonce,
    out: &mut [u8],
) -> Result<usize, Box<dyn Error>> {
    if ciphertext.len() < TAG_SIZE {
        return Err("ciphertext shorter than TAG_SIZE".into());
    }

    // Split ChaCha20 ciphertext from the Poly1305 tag
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);

    if out.len() < ct.len() {
        return Err("out.len < ct.len()".into());
    }

    let in_out = &mut out[..ct.len()];
    in_out.copy_from_slice(ct);

    recv_cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(recv_nonce.to_bytes()),
            b"",
            in_out,
            tag.into(),
        )
        .map_err(|e| format!("aead: {}", e.to_string()))?;

    Ok(in_out.len())
}

async fn read_and_decrypt(
    io_handler: &mut TcpStream,
    // buffer: &mut Vec<u8>,
    nonce: &mut Nonce,
    cipher: &ChaCha20Poly1305,
    data: &mut [u8],
) -> io::Result<usize> {
    // if !buffer.is_empty() {
    //     let n = cmp::min(data.len(), buffer.len());
    //     data.copy_from_slice(&buffer[..n]);
    //     let mut leftover_portion = vec![
    //         0;
    //         buffer
    //             .len()
    //             .checked_sub(n)
    //             .expect("leftover calculation failed")
    //     ];
    //     leftover_portion.clone_from_slice(&buffer[n..]);
    //     // TODO!!!!
    //     *buffer = leftover_portion;

    //     return Ok(n);
    // }

    let mut sealed_frame = [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
    io_handler.read_exact(&mut sealed_frame).await?;

    // decrypt the frame
    let mut frame = [0_u8; TOTAL_FRAME_SIZE];
    let res = decrypt(&sealed_frame, &cipher, &nonce, &mut frame);

    if let Err(err) = res {
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }

    nonce.increment();
    // end decryption

    let chunk_length = u32::from_le_bytes(frame[..4].try_into().expect("chunk framing failed"));

    if chunk_length as usize > DATA_MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("chunk is too big: {chunk_length}! max: {DATA_MAX_SIZE}"),
        ));
    }

    let mut chunk = vec![0; chunk_length as usize];
    chunk.clone_from_slice(
        &frame[DATA_LEN_SIZE
            ..(DATA_LEN_SIZE
                .checked_add(chunk_length as usize)
                .expect("chunk size addition overflow"))],
    );

    let n = cmp::min(data.len(), chunk.len());
    data[..n].copy_from_slice(&chunk[..n]);
    // buffer.copy_from_slice(&chunk[n..]);

    Ok(n)
}

fn encrypt(
    chunk: &[u8],
    send_cipher: &ChaCha20Poly1305,
    send_nonce: &Nonce,
    sealed_frame: &mut [u8; TAG_SIZE + TOTAL_FRAME_SIZE],
) -> Result<(), Box<dyn Error>> {
    assert!(!chunk.is_empty(), "chunk is empty");
    assert!(
        chunk.len() <= TOTAL_FRAME_SIZE - DATA_LEN_SIZE,
        "chunk is too big: {}! max: {}",
        chunk.len(),
        DATA_MAX_SIZE,
    );
    sealed_frame[..DATA_LEN_SIZE].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    sealed_frame[DATA_LEN_SIZE..DATA_LEN_SIZE + chunk.len()].copy_from_slice(chunk);

    let tag = send_cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(send_nonce.to_bytes()),
            b"",
            &mut sealed_frame[..TOTAL_FRAME_SIZE],
        )
        .map_err(|e| format!("aead {}", e))?;

    sealed_frame[TOTAL_FRAME_SIZE..].copy_from_slice(tag.as_slice());

    Ok(())
}

// Writes encrypted frames of `TAG_SIZE` + `TOTAL_FRAME_SIZE`
async fn encrypt_and_write(
    io_handler: &mut TcpStream,
    // send_state: &mut SendState,
    nonce: &mut Nonce,
    cipher: &ChaCha20Poly1305,
    data: &[u8],
) -> io::Result<usize> {
    let mut n = 0_usize;
    let mut data_copy = data;
    while !data_copy.is_empty() {
        let chunk: &[u8];
        if DATA_MAX_SIZE < data.len() {
            chunk = &data[..DATA_MAX_SIZE];
            data_copy = &data_copy[DATA_MAX_SIZE..];
        } else {
            chunk = data_copy;
            data_copy = &[0_u8; 0];
        }
        let sealed_frame = &mut [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
        encrypt(chunk, &cipher, &nonce, sealed_frame)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        nonce.increment();
        // end encryption

        io_handler.write_all(&sealed_frame[..]).await?;
        n = n
            .checked_add(chunk.len())
            .expect("overflow when adding chunk lengths");
    }

    Ok(n)
}

pub async fn handshake_start(
    stream: &mut TcpStream,
    // private_key: PrivateKey,
) -> Result<(), Box<dyn Error>> {
    let private_key = PrivateKey::generate();
    let local_eph_privkey = Scalar::random(&mut OsRng);
    let local_eph_pubkey = X25519_BASEPOINT * local_eph_privkey;

    // send our ephemeral pubkey
    stream
        .write_all(&encode_initial_handshake(&local_eph_pubkey))
        .await?;

    // receive their ephemeral pubkey
    let mut response_len = 0_u8;
    stream
        .read_exact(slice::from_mut(&mut response_len))
        .await?;

    let mut buf = vec![0; response_len as usize];
    stream.read_exact(&mut buf).await?;

    let remote_eph_pubkey = decode_initial_handshake(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("oh noes {}", e)))?;

    let (local_signature, sc_mac, recv_cipher, send_cipher) =
        got_key(&private_key, &local_eph_privkey, &remote_eph_pubkey)?;

    // Share each other's pubkey & challenge signature.
    // NOTE: the data must be encrypted/decrypted using ciphers.
    // let verification_key = private_key.public_key().verification_key;
    let auth_sig_msg = share_auth_signature(
        stream,
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
