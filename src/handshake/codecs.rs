use curve25519_dalek_ng::montgomery::MontgomeryPoint;
use prost::Message as _;
use std::io::Error;
use tendermint_proto::v0_38 as proto;

use super::keys::PublicKey;

pub fn decode_remote_eph_pubkey(bytes: &[u8]) -> Result<MontgomeryPoint, std::io::Error> {
    // go implementation
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L315-L323
    if bytes.len() != 34 || bytes[..2] != [0x0a, 0x20] {
        return Err(Error::other("malformed_handshake"));
    }

    let eph_pubkey_bytes: [u8; 32] = bytes[2..].try_into().expect("framing failed");

    Ok(MontgomeryPoint(eph_pubkey_bytes))
}

pub fn encode_auth_signature(pub_key: &PublicKey, signature: &[u8; 64]) -> Vec<u8> {
    let pub_key = proto::crypto::PublicKey {
        sum: Some(proto::crypto::public_key::Sum::Ed25519(pub_key.to_bytes())),
    };

    let msg = proto::p2p::AuthSigMessage {
        pub_key: Some(pub_key),
        sig: signature.to_vec(),
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

pub fn encode_our_eph_pubkey(eph_pubkey: &MontgomeryPoint) -> Vec<u8> {
    // go implementation:
    // https://github.com/tendermint/tendermint/blob/9e98c74/p2p/conn/secret_connection.go#L307-L312
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x22, 0x0a, 0x20]);
    buf.extend_from_slice(eph_pubkey.as_bytes());
    buf
}
