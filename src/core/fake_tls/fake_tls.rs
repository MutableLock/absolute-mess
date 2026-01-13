use crate::core::fake_tls::external::{construct_client_hello, construct_server_hello};
use rand::{Rng};
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::bytes::{BufMut, Bytes, BytesMut};

fn write_vec_u16(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn write_u24(buf: &mut Vec<u8>, val: u32) {
    buf.push(((val >> 16) & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
    buf.push((val & 0xFF) as u8);
}

const CIPHER_SUITES: [u16; 3] = [
    0x1302, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1301, // TLS_AES_256_GCM_SHA384
];

pub const CONTENT_TYPES: [u8; 2] = [
    0x16, //handshake
    0x17, //application data
];

// Helper: Build a complete TLS record around a handshake message
pub fn build_tls_record(
    content_type: u8,
    legacy_version: [u8; 2], // Usually [0x03, 0x01] or [0x03, 0x03]
    handshake_data: &[u8],   // The full handshake message body (without handshake header)
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(handshake_data.len() + 5);

    // TLS Record Layer Header
    buf.push(content_type); // Content Type: Handshake
    buf.extend_from_slice(&legacy_version); // Legacy Protocol Version (TLS 1.2 usually)

    let record_length_pos = buf.len();
    buf.extend_from_slice(&[0x00, 0x00]); // Placeholder for length

    // Append the actual handshake payload
    buf.extend_from_slice(handshake_data);

    // Now fill in the correct record length
    let payload_len = buf.len() - record_length_pos - 2;
    let record_len_bytes = (payload_len as u16).to_be_bytes();
    buf[record_length_pos..record_length_pos + 2].copy_from_slice(&record_len_bytes);

    buf
}

pub fn build_tls_record_bytes(
    content_type: u8,
    legacy_version: [u8; 2], // Usually [0x03, 0x01] or [0x03, 0x03]
    data: Bytes,
    dst: &mut BytesMut,
)  {
   dst.reserve(5+data.len());

    // TLS Record Layer Header
    dst.put_u8(content_type); // Content Type: data
    dst.put_u8(legacy_version[0]);// Legacy Protocol Version (TLS 1.2 usually)
    dst.put_u8(legacy_version[1]);

    let record_length_pos = dst.len();
    dst.put_u8(0);
    dst.put_u8(0);

    // Append the actual data payload
    dst.extend(data);

    // Now fill in the correct record length
    let payload_len = dst.len() - record_length_pos - 2;
    let record_len_bytes = (payload_len as u16).to_be_bytes();
    dst[record_length_pos..record_length_pos + 2].copy_from_slice(&record_len_bytes);

}

async fn read_tls_record(interface: &mut TcpStream) -> u16 {
    let mut buf = Vec::with_capacity(5);
    interface.read_exact(&mut buf).await.unwrap();
    let length_bytes: [u8; 2] = [buf[3], buf[4]];
    u16::from_be_bytes(length_bytes)
}

pub fn build_client_hello(sni: &str, payload: &[u8; 32], alpns: &[&str]) -> Result<Vec<u8>, ()> {
    let rng = SystemRandom::new();
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random).unwrap();

    // Generate client X25519 keypair
    //@TODO: if needed replace with real key exchange
    let client_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let client_pub = client_priv.compute_public_key().unwrap();

    let data = construct_client_hello(
        &client_random,
        payload,
        client_pub.as_ref(),
        sni,
        &CIPHER_SUITES,
        alpns,
    )?;
    Ok(build_tls_record(
        CONTENT_TYPES[0],
        [0x03, 0x01], // TLS 1.2 legacy version in record
        data.as_slice(),
    ))
}

pub fn build_server_hello(payload: &[u8; 32]) -> Result<Vec<u8>, ()> {
    let rng = SystemRandom::new();
    let mut server_random = [0u8; 32];
    rng.fill(&mut server_random).unwrap();

    let cipher_id = rand::rng().random_range(0..CIPHER_SUITES.iter().len());

    //@TODO: if needed replace with real key exchange
    let server_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let server_pub = server_priv.compute_public_key().unwrap();

    let data = construct_server_hello(
        &server_random,
        payload,
        CIPHER_SUITES[cipher_id],
        server_pub.as_ref(),
    )?;

    Ok(build_tls_record(
        CONTENT_TYPES[0],
        [0x03, 0x01],
        data.as_slice(),
    ))
}

pub async fn perform_tls_handshake_client(
    sni: &str,
    payload: &[u8; 32],
    alpns: &[&str],
    interface: &mut TcpStream,
) {
    let client_hello = build_client_hello(sni, payload, alpns).unwrap();
    interface.write_all(client_hello.as_slice()).await.unwrap();
    interface.flush().await.unwrap();
    let length = read_tls_record(interface).await;
    let mut buffer = Vec::with_capacity(length as usize);
    interface.read_exact(&mut buffer).await.unwrap();
}

pub async fn perform_tls_handshake_server(payload: &[u8; 32], interface: &mut TcpStream) {
    let client_length = read_tls_record(interface).await;
    let mut buffer = Vec::with_capacity(client_length as usize);
    interface.read_exact(&mut buffer).await.unwrap();
    let server_hello = build_server_hello(payload).unwrap();
    interface.write_all(server_hello.as_slice()).await.unwrap();
    interface.flush().await.unwrap();
}
