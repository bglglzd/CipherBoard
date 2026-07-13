use cipherboard_crypto::{
    decode_transport_part, parse_pairing_payload, CipherAccount, CipherSession, CoreError,
    ErrorCode, PairingOffer, PairingResponse, PublicIdentity, Result, SecretBytes, TransportMode,
    MAX_ENCODED_PART_BYTES, MAX_PARTS, OLM_SESSION_VERSION, PROTOCOL_VERSION,
};
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

pub const WIRE_VERSION: u8 = 1;
pub const MAX_REQUEST_BYTES: usize = 5 * 1024 * 1024;
const MAX_ACCOUNT_STATE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 192 * 1024;
const MAX_PAIRING_BYTES: usize = 32 * 1024;

const OP_PROTOCOL_VERSION: i32 = 0;
const OP_CREATE_ACCOUNT: i32 = 1;
const OP_CREATE_OFFER: i32 = 2;
const OP_RESPOND_OFFER: i32 = 3;
const OP_COMPLETE_PAIRING: i32 = 4;
const OP_ENCRYPT: i32 = 5;
const OP_DECRYPT: i32 = 6;
const OP_PARSE_ENVELOPE: i32 = 7;
const OP_PARSE_PAIRING_PAYLOAD: i32 = 8;

/// Invoke a stateless crypto operation through the bounded CBOR wire format.
pub fn dispatch(operation: i32, request: &[u8]) -> SecretBytes {
    if request.len() > MAX_REQUEST_BYTES {
        return error_response(ErrorCode::SizeLimit);
    }
    match dispatch_inner(operation, request) {
        Ok(payload) => success_response(&payload),
        Err(error) => error_response(error.code()),
    }
}

pub(crate) fn error_response(code: ErrorCode) -> SecretBytes {
    let mut encoder = Encoder::new(Vec::with_capacity(8));
    let result = encoder
        .array(3)
        .and_then(|value| value.u8(WIRE_VERSION))
        .and_then(|value| value.u32(code as u32))
        .and_then(|value| value.bytes(&[]));
    if result.is_err() {
        return SecretBytes::from_owned(Vec::new());
    }
    SecretBytes::from_owned(encoder.into_writer())
}

fn success_response(payload: &SecretBytes) -> SecretBytes {
    let mut encoder = Encoder::new(Vec::with_capacity(payload.len().saturating_add(16)));
    let result = encoder
        .array(3)
        .and_then(|value| value.u8(WIRE_VERSION))
        .and_then(|value| value.u32(0))
        .and_then(|value| value.bytes(payload.expose()));
    if result.is_err() {
        encoder.into_writer().zeroize();
        return error_response(ErrorCode::InvalidEncoding);
    }
    SecretBytes::from_owned(encoder.into_writer())
}

fn dispatch_inner(operation: i32, input: &[u8]) -> Result<SecretBytes> {
    match operation {
        OP_PROTOCOL_VERSION => protocol_versions(input),
        OP_CREATE_ACCOUNT => create_account(input),
        OP_CREATE_OFFER => create_offer(input),
        OP_RESPOND_OFFER => respond_offer(input),
        OP_COMPLETE_PAIRING => complete_pairing(input),
        OP_ENCRYPT => encrypt(input),
        OP_DECRYPT => decrypt(input),
        OP_PARSE_ENVELOPE => parse_envelope(input),
        OP_PARSE_PAIRING_PAYLOAD => parse_pairing(input),
        _ => Err(ErrorCode::InvalidInput.into()),
    }
}

fn protocol_versions(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 1)?;
    request.version()?;
    request.finish()?;
    encode_payload(|encoder| {
        encoder
            .array(2)?
            .u8(PROTOCOL_VERSION)?
            .u8(OLM_SESSION_VERSION)?;
        Ok(())
    })
}

fn create_account(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 1)?;
    request.version()?;
    request.finish()?;
    let account = CipherAccount::new();
    let identity = account.public_identity();
    let fingerprint = identity.fingerprint();
    let state = account.serialize_state()?;
    encode_payload(|encoder| {
        encoder.array(4)?;
        encoder.bytes(state.expose())?;
        encode_identity(encoder, identity)?;
        encoder.bytes(&fingerprint)?;
        Ok(())
    })
}

fn create_offer(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 5)?;
    request.version()?;
    let state = request.bytes(MAX_ACCOUNT_STATE_BYTES)?;
    let now = request.u64()?;
    let ttl = request.u64()?;
    let capabilities = request.u32()?;
    request.finish()?;
    let mut account = CipherAccount::deserialize_state(state)?;
    let offer = account.create_pairing_offer(now, ttl, capabilities)?;
    let updated_state = account.serialize_state()?;
    let qr = offer.encode_qr()?;
    encode_payload(|encoder| {
        encoder.array(2)?;
        encoder.bytes(updated_state.expose())?;
        encoder.bytes(qr.as_bytes())?;
        Ok(())
    })
}

fn respond_offer(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 5)?;
    request.version()?;
    let account_state = request.bytes(MAX_ACCOUNT_STATE_BYTES)?;
    let offer_text = request.utf8(MAX_PAIRING_BYTES)?;
    let now = request.u64()?;
    let capabilities = request.u32()?;
    request.finish()?;
    let account = CipherAccount::deserialize_state(account_state)?;
    let offer = PairingOffer::decode_qr(offer_text)?;
    let prepared = account.respond_to_pairing_offer(&offer, now, capabilities)?;
    let response_qr = prepared.response.encode_qr()?;
    let remote = prepared.session.remote_identity();
    let routing_tag = *prepared.session.routing_tag();
    let remote_fingerprint = remote.fingerprint();
    let session_state = prepared.session.serialize_state()?;
    encode_safety_and_remote(
        &session_state,
        None,
        response_qr.as_bytes(),
        &prepared.safety_code,
        remote,
        &routing_tag,
        &remote_fingerprint,
    )
}

fn complete_pairing(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 5)?;
    request.version()?;
    let account_state = request.bytes(MAX_ACCOUNT_STATE_BYTES)?;
    let offer_text = request.utf8(MAX_PAIRING_BYTES)?;
    let response_text = request.utf8(MAX_PAIRING_BYTES)?;
    let now = request.u64()?;
    request.finish()?;
    let mut account = CipherAccount::deserialize_state(account_state)?;
    let offer = PairingOffer::decode_qr(offer_text)?;
    let response = PairingResponse::decode_qr(response_text)?;
    let completed = account.complete_pairing(&offer, &response, now)?;
    let account_state = account.serialize_state()?;
    let remote = completed.session.remote_identity();
    let routing_tag = *completed.session.routing_tag();
    let remote_fingerprint = remote.fingerprint();
    let session_state = completed.session.serialize_state()?;
    encode_safety_and_remote(
        &session_state,
        Some(&account_state),
        &[],
        &completed.safety_code,
        remote,
        &routing_tag,
        &remote_fingerprint,
    )
}

fn encode_safety_and_remote(
    session_state: &SecretBytes,
    account_state: Option<&SecretBytes>,
    response_qr: &[u8],
    safety: &cipherboard_crypto::SafetyCode,
    remote: PublicIdentity,
    routing_tag: &[u8; 16],
    remote_fingerprint: &[u8; 32],
) -> Result<SecretBytes> {
    let decimal = safety.decimal_groups();
    let words = safety.word_code();
    encode_payload(|encoder| {
        encoder.array(if account_state.is_some() { 10 } else { 9 })?;
        if let Some(state) = account_state.as_ref() {
            encoder.bytes(state.expose())?;
        }
        encoder.bytes(session_state.expose())?;
        encoder.bytes(response_qr)?;
        encoder.bytes(safety.hash())?;
        encoder.bytes(decimal.as_bytes())?;
        encoder.bytes(words.as_bytes())?;
        encode_identity(encoder, remote)?;
        encoder.bytes(routing_tag)?;
        encoder.bytes(remote_fingerprint)?;
        Ok(())
    })
}

fn encrypt(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 5)?;
    request.version()?;
    let session_state = request.bytes(MAX_SESSION_STATE_BYTES)?;
    let plaintext = request.bytes(MAX_PLAINTEXT_BYTES)?;
    let capabilities = request.u32()?;
    let mode = match request.u8()? {
        0 => TransportMode::Universal,
        1 => TransportMode::SmsCompact,
        _ => return Err(ErrorCode::InvalidInput.into()),
    };
    request.finish()?;
    let session = CipherSession::deserialize_state(session_state)?;
    let prepared = session.prepare_encrypt(plaintext, capabilities, mode)?;
    encode_payload(|encoder| {
        encoder.array(3)?;
        encoder.bytes(prepared.next_state().expose())?;
        encoder.bytes(prepared.message_id())?;
        encoder.array(
            u64::try_from(prepared.parts().len())
                .map_err(|_| minicbor::encode::Error::message("size"))?,
        )?;
        for part in prepared.parts() {
            encoder.bytes(part.as_bytes())?;
        }
        Ok(())
    })
}

fn decrypt(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 3)?;
    request.version()?;
    let session_state = request.bytes(MAX_SESSION_STATE_BYTES)?;
    let count = request.array_len()?;
    if count == 0 || count > u64::from(MAX_PARTS) {
        return Err(ErrorCode::TooManyParts.into());
    }
    let mut parts = Vec::with_capacity(usize::try_from(count).map_err(|_| ErrorCode::SizeLimit)?);
    for _ in 0..count {
        parts.push(request.utf8(MAX_ENCODED_PART_BYTES)?);
    }
    request.finish()?;
    let session = CipherSession::deserialize_state(session_state)?;
    let prepared = session.prepare_decrypt(parts)?;
    encode_payload(|encoder| {
        encoder.array(3)?;
        encoder.bytes(prepared.next_state().expose())?;
        encoder.bytes(prepared.message_id())?;
        encoder.bytes(prepared.plaintext().expose())?;
        Ok(())
    })
}

fn parse_envelope(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 2)?;
    request.version()?;
    let text = request.utf8(MAX_ENCODED_PART_BYTES)?;
    request.finish()?;
    let part = decode_transport_part(text)?;
    encode_payload(|encoder| {
        encoder.array(7)?;
        encoder.bytes(part.routing_tag())?;
        encoder.bytes(part.message_id())?;
        encoder.u16(part.part_number())?;
        encoder.u16(part.total_parts())?;
        encoder.u32(part.capabilities())?;
        encoder.u8(part.olm_type())?;
        encoder.u32(
            u32::try_from(part.payload().len())
                .map_err(|_| minicbor::encode::Error::message("size"))?,
        )?;
        Ok(())
    })
}

fn parse_pairing(input: &[u8]) -> Result<SecretBytes> {
    let mut request = Request::new(input, 3)?;
    request.version()?;
    let text = request.utf8(MAX_PAIRING_BYTES)?;
    let now = request.u64()?;
    request.finish()?;
    let metadata = parse_pairing_payload(text, now)?;
    let remote = metadata.remote_identity();
    let remote_fingerprint = metadata.remote_identity_fingerprint();
    encode_payload(|encoder| {
        encoder.array(10)?;
        encoder.u8(metadata.payload_type() as u8)?;
        encoder.bytes(metadata.pairing_id())?;
        encode_identity(encoder, remote)?;
        encoder.bytes(&remote_fingerprint)?;
        encoder.bytes(metadata.nonce())?;
        encoder.u32(metadata.capabilities())?;
        encoder.u64(metadata.expires_at().unwrap_or(0))?;
        encoder.u8(u8::from(metadata.is_expired()))?;
        encoder.bytes(metadata.offer_hash())?;
        Ok(())
    })
}

fn encode_identity(
    encoder: &mut Encoder<Vec<u8>>,
    identity: PublicIdentity,
) -> core::result::Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    encoder.bytes(identity.curve25519())?;
    encoder.bytes(identity.ed25519())?;
    Ok(())
}

fn encode_payload<F>(encode: F) -> Result<SecretBytes>
where
    F: FnOnce(
        &mut Encoder<Vec<u8>>,
    ) -> core::result::Result<(), minicbor::encode::Error<std::convert::Infallible>>,
{
    let mut encoder = Encoder::new(Vec::new());
    if encode(&mut encoder).is_err() {
        encoder.into_writer().zeroize();
        return Err(CoreError::from(ErrorCode::InvalidEncoding));
    }
    Ok(SecretBytes::from_owned(encoder.into_writer()))
}

struct Request<'a> {
    decoder: Decoder<'a>,
    input_len: usize,
}

impl<'a> Request<'a> {
    fn new(input: &'a [u8], expected_fields: u64) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        if decoder.array().map_err(|_| ErrorCode::InvalidEncoding)? != Some(expected_fields) {
            return Err(ErrorCode::InvalidEncoding.into());
        }
        Ok(Self {
            decoder,
            input_len: input.len(),
        })
    }

    fn version(&mut self) -> Result<()> {
        if self.u8()? == WIRE_VERSION {
            Ok(())
        } else {
            Err(ErrorCode::UnsupportedVersion.into())
        }
    }

    fn u8(&mut self) -> Result<u8> {
        self.decoder
            .u8()
            .map_err(|_| ErrorCode::InvalidEncoding.into())
    }

    fn u32(&mut self) -> Result<u32> {
        self.decoder
            .u32()
            .map_err(|_| ErrorCode::InvalidEncoding.into())
    }

    fn u64(&mut self) -> Result<u64> {
        self.decoder
            .u64()
            .map_err(|_| ErrorCode::InvalidEncoding.into())
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let bytes = self
            .decoder
            .bytes()
            .map_err(|_| ErrorCode::InvalidEncoding)?;
        if bytes.len() > maximum {
            Err(ErrorCode::SizeLimit.into())
        } else {
            Ok(bytes)
        }
    }

    fn utf8(&mut self, maximum: usize) -> Result<&'a str> {
        core::str::from_utf8(self.bytes(maximum)?).map_err(|_| ErrorCode::InvalidEncoding.into())
    }

    fn array_len(&mut self) -> Result<u64> {
        self.decoder
            .array()
            .map_err(|_| CoreError::from(ErrorCode::InvalidEncoding))?
            .ok_or_else(|| CoreError::from(ErrorCode::InvalidEncoding))
    }

    fn finish(self) -> Result<()> {
        if self.decoder.position() == self.input_len {
            Ok(())
        } else {
            Err(ErrorCode::InvalidEncoding.into())
        }
    }
}
