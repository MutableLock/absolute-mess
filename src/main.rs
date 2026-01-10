use crate::core::fake_tls::fake_tls::{build_client_hello, build_server_hello};

mod core;

fn main() {
    let alpns = ["h2"];
    let payload = [0u8;32];
    let server_hello = build_server_hello(&payload).unwrap();
    let client_hello = build_client_hello("yahoo.com", &payload, &alpns).unwrap();

    println!("{}, {}", client_hello.len(), server_hello.len());
}
