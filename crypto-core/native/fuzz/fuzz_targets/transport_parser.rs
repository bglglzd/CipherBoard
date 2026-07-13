#![no_main]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libfuzzer_sys::fuzz_target;

// Compile the production parser directly. Depending on the complete crypto crate would also
// build its Android-facing cdylib, which is unrelated to this target and conflicts with the
// libFuzzer process entry point on Windows.
#[path = "../../src/error.rs"]
mod error;
pub use error::{CoreError, ErrorCode, Result};

pub const PROTOCOL_VERSION: u8 = 1;

#[path = "../../src/envelope.rs"]
#[allow(dead_code)]
mod envelope;
use envelope::{
    decode_transport_part, encode_transport_parts, TransportMode, MAX_ENCODED_PART_BYTES,
};

const PREFIX: &str = "CB1:";
const ROUTING_TAG: [u8; 16] = [0x42; 16];
const MESSAGE_ID: [u8; 16] = [0x24; 16];
const MAX_ROUND_TRIP_PAYLOAD: usize = 4 * 1024;

fuzz_target!(|input: &[u8]| {
    let Some((&mode, payload)) = input.split_first() else {
        return;
    };

    match mode % 3 {
        // Exercise prefix, alphabet, UTF-8, base64url, size, and trailing-data checks.
        0 => {
            if let Ok(text) = core::str::from_utf8(payload) {
                let _ = decode_transport_part(text);
            }
        }
        // Treat fuzzer bytes as the decoded CBOR body so mutations immediately reach
        // the strict canonical-CBOR parser instead of having to discover base64 first.
        1 => {
            let encoded_len = payload.len().div_ceil(3).saturating_mul(4);
            if PREFIX.len().saturating_add(encoded_len) <= MAX_ENCODED_PART_BYTES {
                let mut text = String::with_capacity(PREFIX.len() + encoded_len);
                text.push_str(PREFIX);
                URL_SAFE_NO_PAD.encode_string(payload, &mut text);
                let _ = decode_transport_part(&text);
            }
        }
        // Keep valid envelopes in the corpus and exercise encode/decode invariants.
        _ => {
            if payload.len() <= MAX_ROUND_TRIP_PAYLOAD {
                if let Ok(parts) = encode_transport_parts(
                    ROUTING_TAG,
                    MESSAGE_ID,
                    1,
                    payload,
                    0,
                    TransportMode::Universal,
                ) {
                    for part in parts {
                        let decoded = decode_transport_part(&part)
                            .expect("the transport encoder must produce parseable envelopes");
                        assert_eq!(decoded.routing_tag(), &ROUTING_TAG);
                        assert_eq!(decoded.message_id(), &MESSAGE_ID);
                        assert_eq!(decoded.olm_type(), 1);
                    }
                }
            }
        }
    }
});
