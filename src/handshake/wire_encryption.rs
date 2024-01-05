use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace},
    ChaCha20Poly1305,
};
use std::{cmp, error::Error, io};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::handshake::Nonce;

const TAG_SIZE: usize = 16;
const DATA_MAX_SIZE: usize = 1024;

/// 4 + 1024 == 1028 total frame size
const DATA_LEN_SIZE: usize = 4;
const TOTAL_FRAME_SIZE: usize = DATA_MAX_SIZE + DATA_LEN_SIZE;

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
        .map_err(|e| format!("aead: {}", e))?;

    Ok(in_out.len())
}

pub async fn read_and_decrypt(
    io_handler: &mut OwnedReadHalf,
    nonce: &mut Nonce,
    cipher: &ChaCha20Poly1305,
    data: &mut [u8],
) -> io::Result<usize> {
    let mut sealed_frame = [0_u8; TAG_SIZE + TOTAL_FRAME_SIZE];
    io_handler.read_exact(&mut sealed_frame).await?;

    // decrypt the frame
    let mut frame = [0_u8; TOTAL_FRAME_SIZE];
    let res = decrypt(&sealed_frame, cipher, nonce, &mut frame);

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
pub async fn encrypt_and_write(
    io_handler: &mut OwnedWriteHalf,
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
        encrypt(chunk, cipher, nonce, sealed_frame)
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
