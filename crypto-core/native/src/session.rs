use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use vodozemac::olm::{DecryptionError, OlmMessage, Session, SessionConfig, SessionPickle};
use zeroize::Zeroize;

use crate::{
    encode_transport_parts,
    envelope::{random_message_id, reassemble_transport_parts},
    CoreError, ErrorCode, PublicIdentity, Result, SecretBytes, TransportMode,
};

const SESSION_STATE_MAGIC: &[u8; 4] = b"CBS1";
const SESSION_STATE_VERSION: u8 = 1;
const MAX_SESSION_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 192 * 1024;
const MAX_SEEN_MESSAGE_IDS: usize = 4096;
const INNER_PAYLOAD_FIELDS: u64 = 4;

#[derive(Serialize, Deserialize)]
struct SessionState {
    version: u8,
    local_curve: [u8; 32],
    local_ed: [u8; 32],
    remote_curve: [u8; 32],
    remote_ed: [u8; 32],
    routing_tag: [u8; 16],
    seen_message_ids: Vec<[u8; 16]>,
    session: SessionPickle,
}

/// A vodozemac Olm v2 session plus bounded replay metadata.
pub struct CipherSession {
    inner: Session,
    local_identity: PublicIdentity,
    remote_identity: PublicIdentity,
    routing_tag: [u8; 16],
    seen_message_ids: Vec<[u8; 16]>,
}

impl CipherSession {
    pub(crate) fn from_live(
        inner: Session,
        local_identity: PublicIdentity,
        remote_identity: PublicIdentity,
    ) -> Self {
        let routing_tag = local_identity.routing_tag(&remote_identity);
        Self {
            inner,
            local_identity,
            remote_identity,
            routing_tag,
            seen_message_ids: Vec::new(),
        }
    }

    pub(crate) fn encrypt_initial(&mut self, plaintext: &[u8]) -> Result<OlmMessage> {
        self.inner
            .encrypt(plaintext)
            .map_err(|_| CoreError::new(ErrorCode::CryptoFailure))
    }

    pub const fn local_identity(&self) -> PublicIdentity {
        self.local_identity
    }

    pub const fn remote_identity(&self) -> PublicIdentity {
        self.remote_identity
    }

    pub const fn routing_tag(&self) -> &[u8; 16] {
        &self.routing_tag
    }

    /// Serialize ratchet and replay state for Keystore-backed storage.
    pub fn serialize_state(&self) -> Result<SecretBytes> {
        let state = SessionState {
            version: SESSION_STATE_VERSION,
            local_curve: *self.local_identity.curve25519(),
            local_ed: *self.local_identity.ed25519(),
            remote_curve: *self.remote_identity.curve25519(),
            remote_ed: *self.remote_identity.ed25519(),
            routing_tag: self.routing_tag,
            seen_message_ids: self.seen_message_ids.clone(),
            session: self.inner.pickle(),
        };
        let mut payload = serde_json::to_vec(&state).map_err(|_| ErrorCode::InvalidState)?;
        if payload.len() > MAX_SESSION_STATE_BYTES.saturating_sub(SESSION_STATE_MAGIC.len()) {
            payload.zeroize();
            return Err(ErrorCode::SizeLimit.into());
        }
        let mut bytes = Vec::with_capacity(SESSION_STATE_MAGIC.len() + payload.len());
        bytes.extend_from_slice(SESSION_STATE_MAGIC);
        bytes.extend_from_slice(&payload);
        payload.zeroize();
        Ok(SecretBytes::new(bytes))
    }

    /// Restore ratchet state after authenticated storage decryption.
    pub fn deserialize_state(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= SESSION_STATE_MAGIC.len()
            || bytes.len() > MAX_SESSION_STATE_BYTES
            || bytes.get(..SESSION_STATE_MAGIC.len()) != Some(SESSION_STATE_MAGIC)
        {
            return Err(ErrorCode::InvalidState.into());
        }
        let state: SessionState = serde_json::from_slice(&bytes[SESSION_STATE_MAGIC.len()..])
            .map_err(|_| CoreError::new(ErrorCode::InvalidState))?;
        if state.version != SESSION_STATE_VERSION
            || state.seen_message_ids.len() > MAX_SEEN_MESSAGE_IDS
        {
            return Err(ErrorCode::InvalidState.into());
        }
        let local_identity = PublicIdentity::new(state.local_curve, state.local_ed);
        let remote_identity = PublicIdentity::new(state.remote_curve, state.remote_ed);
        if local_identity.routing_tag(&remote_identity) != state.routing_tag {
            return Err(ErrorCode::InvalidState.into());
        }
        let inner = Session::from_pickle(state.session);
        if inner.session_config() != SessionConfig::version_2() {
            return Err(ErrorCode::InvalidState.into());
        }
        Ok(Self {
            inner,
            local_identity,
            remote_identity,
            routing_tag: state.routing_tag,
            seen_message_ids: state.seen_message_ids,
        })
    }

    /// Consume the in-memory snapshot and prepare a durable send transaction.
    /// Commit `next_state` and the returned parts atomically before inserting
    /// any part into an external application's `InputConnection`.
    pub fn prepare_encrypt(
        mut self,
        plaintext: &[u8],
        capabilities: u32,
        mode: TransportMode,
    ) -> Result<PreparedOutbound> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        let message_id = random_message_id()?;
        let inner_payload = encode_inner_payload(message_id, capabilities, plaintext)?;
        let olm = self
            .inner
            .encrypt(inner_payload.expose())
            .map_err(|_| CoreError::new(ErrorCode::CryptoFailure))?;
        let (olm_type, payload) = olm.to_parts();
        let olm_type = u8::try_from(olm_type).map_err(|_| ErrorCode::CryptoFailure)?;
        let parts = encode_transport_parts(
            self.routing_tag,
            message_id,
            olm_type,
            &payload,
            capabilities,
            mode,
        )?;
        let next_state = self.serialize_state()?;
        Ok(PreparedOutbound {
            message_id,
            parts,
            next_state,
        })
    }

    /// Consume the in-memory snapshot and prepare a durable receive
    /// transaction. Commit `next_state` before showing `plaintext`.
    pub fn prepare_decrypt<'a, I>(mut self, parts: I) -> Result<PreparedInbound>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let reassembled = reassemble_transport_parts(parts, &self.routing_tag)?;
        let message_id = *reassembled.message_id();
        if self.seen_message_ids.contains(&message_id) {
            return Err(ErrorCode::Replay.into());
        }
        let olm =
            OlmMessage::from_parts(usize::from(reassembled.olm_type()), reassembled.payload())
                .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
        let inner_payload = SecretBytes::new(self.inner.decrypt(&olm).map_err(|error| {
            if matches!(error, DecryptionError::MissingMessageKey(_)) {
                CoreError::new(ErrorCode::Replay)
            } else {
                CoreError::new(ErrorCode::CryptoFailure)
            }
        })?);
        let plaintext =
            decode_inner_payload(&inner_payload, &message_id, reassembled.capabilities())?;
        self.seen_message_ids.push(message_id);
        if self.seen_message_ids.len() > MAX_SEEN_MESSAGE_IDS {
            self.seen_message_ids.remove(0);
        }
        let next_state = self.serialize_state()?;
        Ok(PreparedInbound {
            message_id,
            plaintext,
            next_state,
        })
    }
}

fn encode_inner_payload(
    message_id: [u8; 16],
    capabilities: u32,
    plaintext: &[u8],
) -> Result<SecretBytes> {
    let mut encoder = Encoder::new(Vec::with_capacity(plaintext.len().saturating_add(32)));
    encoder
        .array(INNER_PAYLOAD_FIELDS)
        .and_then(|value| value.u8(SESSION_STATE_VERSION))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .bytes(&message_id)
        .and_then(|value| value.u32(capabilities))
        .and_then(|value| value.bytes(plaintext))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    Ok(SecretBytes::new(encoder.into_writer()))
}

fn decode_inner_payload(
    payload: &SecretBytes,
    expected_message_id: &[u8; 16],
    expected_capabilities: u32,
) -> Result<SecretBytes> {
    let mut decoder = Decoder::new(payload.expose());
    if decoder.array().map_err(|_| ErrorCode::InvalidEncoding)? != Some(INNER_PAYLOAD_FIELDS)
        || decoder.u8().map_err(|_| ErrorCode::InvalidEncoding)? != SESSION_STATE_VERSION
    {
        return Err(ErrorCode::InvalidTranscript.into());
    }
    let message_id: [u8; 16] = decoder
        .bytes()
        .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?
        .try_into()
        .map_err(|_| CoreError::new(ErrorCode::InvalidTranscript))?;
    let capabilities = decoder.u32().map_err(|_| ErrorCode::InvalidEncoding)?;
    let plaintext = decoder.bytes().map_err(|_| ErrorCode::InvalidEncoding)?;
    if &message_id != expected_message_id
        || capabilities != expected_capabilities
        || plaintext.len() > MAX_PLAINTEXT_BYTES
        || decoder.position() != payload.len()
    {
        return Err(ErrorCode::InvalidTranscript.into());
    }
    Ok(SecretBytes::new(plaintext.to_vec()))
}

/// Atomic send operation output.
pub struct PreparedOutbound {
    message_id: [u8; 16],
    parts: Vec<String>,
    next_state: SecretBytes,
}

impl PreparedOutbound {
    pub const fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    pub fn next_state(&self) -> &SecretBytes {
        &self.next_state
    }

    pub fn into_parts_and_state(self) -> (Vec<String>, SecretBytes) {
        (self.parts, self.next_state)
    }
}

/// Atomic receive operation output. Plaintext and next state zeroize on drop.
pub struct PreparedInbound {
    message_id: [u8; 16],
    plaintext: SecretBytes,
    next_state: SecretBytes,
}

impl PreparedInbound {
    pub const fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    pub fn plaintext(&self) -> &SecretBytes {
        &self.plaintext
    }

    pub fn next_state(&self) -> &SecretBytes {
        &self.next_state
    }

    pub fn into_plaintext_and_state(self) -> (SecretBytes, SecretBytes) {
        (self.plaintext, self.next_state)
    }
}
