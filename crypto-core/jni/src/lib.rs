//! Stateless JNI entry point for the `CipherBoard` crypto core.

mod wire;

use std::panic::{catch_unwind, AssertUnwindSafe};

use cipherboard_crypto::ErrorCode;
use jni::{
    objects::{JByteArray, JObject},
    sys::{jbyteArray, jint},
    JNIEnv,
};
use zeroize::Zeroize;

pub use wire::{dispatch, MAX_REQUEST_BYTES, WIRE_VERSION};

/// The only JNI operation exposed by the native library. No stateful native
/// handles cross this boundary.
#[no_mangle]
pub extern "system" fn Java_org_cipherboard_cryptocore_NativeBridge_nativeInvoke(
    env: JNIEnv<'_>,
    _instance: JObject<'_>,
    operation: jint,
    request: JByteArray<'_>,
) -> jbyteArray {
    let response = match env.get_array_length(&request) {
        Ok(length) if usize::try_from(length).is_ok_and(|length| length <= MAX_REQUEST_BYTES) => {
            match env.convert_byte_array(&request) {
                Ok(mut input) => {
                    let response = catch_unwind(AssertUnwindSafe(|| dispatch(operation, &input)))
                        .unwrap_or_else(|_| wire::error_response(ErrorCode::CryptoFailure));
                    input.zeroize();
                    response
                }
                Err(_) => wire::error_response(ErrorCode::InvalidInput),
            }
        }
        _ => wire::error_response(ErrorCode::SizeLimit),
    };

    let result = env.byte_array_from_slice(response.expose());
    drop(response);
    result.map_or(std::ptr::null_mut(), JByteArray::into_raw)
}
