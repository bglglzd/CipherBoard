#![forbid(unsafe_code)]

//! `CipherBoard`'s offline Olm protocol core.
//!
//! Stateful operations are intentionally transactional. Encryption and
//! decryption return a serialized next state without modifying the source
//! session. Android must durably commit that state before exposing the
//! ciphertext or plaintext.

mod account;
mod envelope;
mod error;
pub mod ffi;
mod pairing;
mod secret;
mod session;

pub use account::{CipherAccount, PublicIdentity};
pub use envelope::{
    decode_transport_part, encode_transport_parts, estimate_part_count, reassemble_transport_parts,
    EnvelopePart, ReassembledMessage, TransportMode, MAX_ENCODED_PART_BYTES, MAX_MESSAGE_BYTES,
    MAX_PARTS,
};
pub use error::{CoreError, ErrorCode, Result};
pub use pairing::{
    PairingCompletion, PairingOffer, PairingResponse, PreparedPairingResponse, SafetyCode,
    MAX_OFFER_TTL_SECONDS,
};
pub use secret::SecretBytes;
pub use session::{CipherSession, PreparedInbound, PreparedOutbound};

/// `CipherBoard` wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u8 = 1;

/// Olm session configuration used by every session.
pub const OLM_SESSION_VERSION: u8 = 2;
