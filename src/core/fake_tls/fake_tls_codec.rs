use std::io;
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use crate::core::fake_tls::fake_tls;
use crate::core::fake_tls::fake_tls::build_tls_record_bytes;

pub struct FakeTLSCodec {

}

impl Decoder for FakeTLSCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 4 bytes for length
        if src.len() < 5 {
            return Ok(None);
        }
        let content_type = src[0];
        let version = &src[1..3];

        if content_type != fake_tls::CONTENT_TYPES[1] || version != [0x03, 0x01] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TLS record"));
        }

        let len = u16::from_be_bytes([src[3], src[4]]) as usize;

        if len > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "record too large"));
        }
        // Check if full frame is available
        if src.len() < 5 + len {
            return Ok(None);
        }

        // Consume length
        src.advance(5);

        // Read payload

        Ok(Some(src.split_to(len)))
    }
}

impl Encoder<Bytes> for FakeTLSCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {

        build_tls_record_bytes(fake_tls::CONTENT_TYPES[1], [0x03, 0x01], item, dst);

        Ok(())
    }
}