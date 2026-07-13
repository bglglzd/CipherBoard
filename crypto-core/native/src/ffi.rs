//! Small, safe surface intended to sit behind the platform JNI adapter.
//!
//! JNI pointer conversion and Android lifecycle ownership are deliberately not
//! implemented in this core crate because they require `unsafe`. A separate
//! Android adapter may call these validation helpers and map the stable code.

use crate::{decode_transport_part, ErrorCode};

/// Protocol implementation version for platform compatibility checks.
pub const fn protocol_version() -> u8 {
    crate::PROTOCOL_VERSION
}

/// Validate a transport part without returning ciphertext through diagnostics.
pub fn validate_transport_part(text: &str) -> i32 {
    match decode_transport_part(text) {
        Ok(_) => 0,
        Err(error) => error.code() as i32,
    }
}

/// Stable generic invalid-input code for adapters that cannot decode a call.
pub const fn invalid_input_code() -> i32 {
    ErrorCode::InvalidInput as i32
}
