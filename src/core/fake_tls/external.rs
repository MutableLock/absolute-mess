


/**
Copyright (c) 2021-2023 Alex Lau <github@alau.ca>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/



pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;




//Thanks for cfal/shoes crate for providing proper source in rust. https://github.com/cfal/shoes/blob/master/src/reality/reality_tls13_messages.rs


/// Construct TLS 1.3 ClientHello message
///
/// Returns handshake message bytes (without record header)
///
/// # Arguments
/// * `client_random` - 32 bytes client random
/// * `session_id` - 32 bytes session ID
/// * `client_public_key` - X25519 public key bytes
/// * `server_name` - SNI hostname
/// * `cipher_suites` - Cipher suite IDs to offer (e.g., &[0x1301, 0x1302, 0x1303])
/// * `alpn_protocols` - ALPN protocols to offer (e.g., &["h2", "http/1.1"])
pub fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8],
    server_name: &str,
    cipher_suites: &[u16],
    alpn_protocols: &[&str],
) -> Result<Vec<u8>, ()> {
    let mut hello = Vec::with_capacity(512);

    // Handshake message type: ClientHello (0x01)
    hello.push(0x01);

    // Placeholder for handshake message length (3 bytes)
    let length_offset = hello.len();
    hello.extend_from_slice(&[0u8; 3]);

    // TLS version: 3.3 (TLS 1.2 for compatibility)
    hello.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Client random (32 bytes)
    hello.extend_from_slice(client_random);

    // Session ID length (1 byte) + Session ID (32 bytes)
    hello.push(32);
    hello.extend_from_slice(session_id);

    // Cipher suites
    let cipher_suites_len = (cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
    for &suite in cipher_suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods (1 method: null)
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0u8; 2]); // Placeholder for extensions length

    let mut extensions = Vec::new();

    // server_name extension (type 0)
    {
        let server_name_bytes = server_name.as_bytes();
        let server_name_len = server_name_bytes.len();

        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        let ext_len = 5 + server_name_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&((server_name_len + 3) as u16).to_be_bytes()); // Server name list length
        extensions.push(0x00); // Name type: host_name
        extensions.extend_from_slice(&(server_name_len as u16).to_be_bytes()); // Name length
        extensions.extend_from_slice(server_name_bytes); // Server name
    }

    // supported_versions extension (type 43)
    {
        extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
        extensions.extend_from_slice(&[0x00, 0x03]); // Extension length: 3
        extensions.push(0x02); // Supported versions length: 2
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    }

    // supported_groups extension (type 10)
    {
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Supported groups length: 2
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    }

    // key_share extension (type 51)
    {
        extensions.extend_from_slice(&[0x00, 0x33]); // Extension type: key_share
        let key_share_len = 2 + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_len as u16).to_be_bytes()); // Extension length
        let key_share_list_len = 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_list_len as u16).to_be_bytes()); // Key share list length
        extensions.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
        extensions.extend_from_slice(&(client_public_key.len() as u16).to_be_bytes()); // Key length
        extensions.extend_from_slice(client_public_key); // Public key
    }

    // signature_algorithms extension (type 13)
    {
        extensions.extend_from_slice(&[0x00, 0x0d]); // Extension type: signature_algorithms
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Signature algorithms length: 2
        extensions.extend_from_slice(&[0x08, 0x07]); // ed25519
    }

    // ALPN extension (type 16)
    if !alpn_protocols.is_empty() {
        extensions.extend_from_slice(&[0x00, 0x10]); // Extension type: ALPN (16)

        // Calculate total length of protocol list
        let protocols_list_len: usize = alpn_protocols
            .iter()
            .map(|p| 1 + p.len()) // 1 byte length prefix + protocol bytes
            .sum();

        // Extension length = 2 (list length field) + protocols_list_len
        let ext_len = 2 + protocols_list_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());

        // Protocol list length
        extensions.extend_from_slice(&(protocols_list_len as u16).to_be_bytes());

        // Each protocol: 1 byte length + protocol string
        for protocol in alpn_protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol.as_bytes());
        }
    }

    // Write extensions length
    let extensions_length = extensions.len();
    hello[extensions_offset..extensions_offset + 2]
        .copy_from_slice(&(extensions_length as u16).to_be_bytes());

    // Append extensions
    hello.extend_from_slice(&extensions);

    // Write handshake message length
    let message_length = hello.len() - 4; // Exclude type (1) and length (3)
    hello[length_offset..length_offset + 3]
        .copy_from_slice(&(message_length as u32).to_be_bytes()[1..]);

    Ok(hello)
}


/// Construct ServerHello message
///
/// # Arguments
/// * `server_random` - 32 bytes of server random
/// * `session_id` - Session ID from ClientHello (for compatibility)
/// * `cipher_suite` - Selected cipher suite (e.g., 0x1301)
/// * `key_share_data` - Server's X25519 public key (32 bytes)
pub fn construct_server_hello(
    server_random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    key_share_data: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut server_hello = Vec::new();

    // ServerHello structure:
    // - handshake_type (1 byte) = 2
    // - length (3 bytes)
    // - version (2 bytes) = 0x0303 (TLS 1.2 for compatibility)
    // - random (32 bytes)
    // - session_id_length (1 byte)
    // - session_id (variable)
    // - cipher_suite (2 bytes)
    // - compression_method (1 byte) = 0
    // - extensions_length (2 bytes)
    // - extensions (variable)

    let mut payload = Vec::new();

    // Version: 0x0303 (TLS 1.2 for compatibility)
    payload.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Random (32 bytes)
    payload.extend_from_slice(server_random);

    // Session ID
    payload.push(session_id.len() as u8);
    payload.extend_from_slice(session_id);

    // Cipher suite
    payload.extend_from_slice(&cipher_suite.to_be_bytes());

    // Compression method = 0
    payload.push(0x00);

    // Extensions
    let mut extensions = Vec::new();

    // supported_versions extension (type=43)
    extensions.extend_from_slice(&[0x00, 0x2b]); // type = 43
    extensions.extend_from_slice(&[0x00, 0x02]); // length = 2
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // key_share extension (type=51)
    let key_share_length = 2 + 2 + key_share_data.len(); // group + length + data
    extensions.extend_from_slice(&[0x00, 0x33]); // type = 51
    extensions.extend_from_slice(&(key_share_length as u16).to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x1d]); // group = X25519 (0x001d)
    extensions.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share_data);

    // Extensions length
    payload.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions);

    // Handshake header
    server_hello.push(HANDSHAKE_TYPE_SERVER_HELLO);

    // Payload length (3 bytes, big-endian)
    let length_bytes = [
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    server_hello.extend_from_slice(&length_bytes);
    server_hello.extend_from_slice(&payload);

    Ok(server_hello)
}


/// Write TLS record header
///
/// # Arguments
/// * `record_type` - TLS record type (0x16 for Handshake, 0x17 for ApplicationData)
/// * `length` - Length of record payload
pub fn write_record_header(record_type: u8, length: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(record_type);
    header.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]); // Version: TLS 1.2
    header.extend_from_slice(&length.to_be_bytes());
    header
}