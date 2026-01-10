use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{Read, Write};
use rand::{rng, Rng, RngCore};
use crate::core::fake_tls::external::{construct_client_hello, construct_server_hello};

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


pub fn build_client_hello(sni: &str,
                          payload: &[u8; 32],alpns: &[&str]) -> Result<Vec<u8>, ()>{
    let rng = SystemRandom::new();
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random).unwrap();

    // Generate client X25519 keypair
    //@TODO: if needed replace with real key exchange
    let client_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let client_pub = client_priv.compute_public_key().unwrap();


    Ok(construct_client_hello(&client_random, payload, client_pub.as_ref(), sni, &CIPHER_SUITES, alpns)?)
}

pub fn build_server_hello(payload: &[u8; 32]) -> Result<Vec<u8>, ()> {
    let rng = SystemRandom::new();
    let mut server_random = [0u8; 32];
    rng.fill(&mut server_random).unwrap();
    
    let cipher_id = rand::rng().random_range(0..CIPHER_SUITES.iter().len());
    
    //@TODO: if needed replace with real key exchange
    let server_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let server_pub = server_priv.compute_public_key().unwrap();
    
    Ok(construct_server_hello(&server_random, payload, CIPHER_SUITES[cipher_id], server_pub.as_ref())?)
}

pub fn perform_tls_handshake_client<T: Read + Write>(

    interface: &mut T,

) {



 //   interface.write_all(client_hello.as_slice()).unwrap();
    interface.flush().unwrap();
    let mut buffer = [0u8; 127];
    interface.read_exact(&mut buffer).unwrap();
}
