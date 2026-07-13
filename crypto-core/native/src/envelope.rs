use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::{data::Type, Decoder, Encoder};

use crate::{CoreError, ErrorCode, Result, PROTOCOL_VERSION};

const PREFIX: &str = "CB1:";
const ENVELOPE_FIELDS: u64 = 9;
const MAX_MAP_FIELDS: u64 = 32;
const OPTIONAL_FIELD_START: u64 = 128;
const UNIVERSAL_CHUNK_BYTES: usize = 16 * 1024;
// Keeps every complete CB1 envelope within one 153-character concatenated GSM segment,
// including the worst-case part counters and capability value.
const SMS_CHUNK_BYTES: usize = 48;
const MAX_OPTIONAL_VALUE_BYTES: usize = 1024;

/// Maximum decoded Olm message size accepted by the parser.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
/// Maximum number of ciphertext transport parts.
pub const MAX_PARTS: u16 = 128;
/// Maximum size of one textual `CB1:` part.
pub const MAX_ENCODED_PART_BYTES: usize = 32 * 1024;

/// Transport sizing policy. Both variants use the same authenticated Olm data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportMode {
    Universal,
    SmsCompact,
}

impl TransportMode {
    const fn chunk_bytes(self) -> usize {
        match self {
            Self::Universal => UNIVERSAL_CHUNK_BYTES,
            Self::SmsCompact => SMS_CHUNK_BYTES,
        }
    }
}

/// One strictly decoded transport part.
pub struct EnvelopePart {
    routing_tag: [u8; 16],
    message_id: [u8; 16],
    olm_type: u8,
    payload: Vec<u8>,
    part_number: u16,
    total_parts: u16,
    capabilities: u32,
}

impl EnvelopePart {
    pub const fn routing_tag(&self) -> &[u8; 16] {
        &self.routing_tag
    }

    pub const fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    pub const fn part_number(&self) -> u16 {
        self.part_number
    }

    pub const fn total_parts(&self) -> u16 {
        self.total_parts
    }

    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }

    pub const fn olm_type(&self) -> u8 {
        self.olm_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Fully reassembled Olm transport message.
pub struct ReassembledMessage {
    routing_tag: [u8; 16],
    message_id: [u8; 16],
    olm_type: u8,
    payload: Vec<u8>,
    capabilities: u32,
}

impl ReassembledMessage {
    pub const fn routing_tag(&self) -> &[u8; 16] {
        &self.routing_tag
    }

    pub const fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    pub const fn olm_type(&self) -> u8 {
        self.olm_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }
}

/// Estimate the number of transport parts for an Olm payload length.
pub fn estimate_part_count(payload_bytes: usize, mode: TransportMode) -> Result<u16> {
    if payload_bytes > MAX_MESSAGE_BYTES {
        return Err(ErrorCode::SizeLimit.into());
    }
    let chunks = payload_bytes.max(1).div_ceil(mode.chunk_bytes());
    u16::try_from(chunks)
        .ok()
        .filter(|count| *count <= MAX_PARTS)
        .ok_or_else(|| CoreError::new(ErrorCode::TooManyParts))
}

pub(crate) fn random_message_id() -> Result<[u8; 16]> {
    let mut id = [0_u8; 16];
    getrandom::getrandom(&mut id).map_err(|_| CoreError::new(ErrorCode::RandomFailure))?;
    Ok(id)
}

/// Encode one Olm message into deterministic CBOR, base64url `CB1:` parts.
pub fn encode_transport_parts(
    routing_tag: [u8; 16],
    message_id: [u8; 16],
    olm_type: u8,
    payload: &[u8],
    capabilities: u32,
    mode: TransportMode,
) -> Result<Vec<String>> {
    if olm_type > 1 || payload.len() > MAX_MESSAGE_BYTES {
        return Err(ErrorCode::InvalidInput.into());
    }
    let total = estimate_part_count(payload.len(), mode)?;
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[]]
    } else {
        payload.chunks(mode.chunk_bytes()).collect()
    };
    let mut output = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let part_number = u16::try_from(index + 1).map_err(|_| ErrorCode::TooManyParts)?;
        let binary = encode_part_binary(
            routing_tag,
            message_id,
            olm_type,
            chunk,
            part_number,
            total,
            capabilities,
        )?;
        let mut text = String::with_capacity(PREFIX.len() + binary.len().div_ceil(3) * 4);
        text.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(binary, &mut text);
        if text.len() > MAX_ENCODED_PART_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        output.push(text);
    }
    Ok(output)
}

fn encode_part_binary(
    routing_tag: [u8; 16],
    message_id: [u8; 16],
    olm_type: u8,
    payload: &[u8],
    part_number: u16,
    total_parts: u16,
    capabilities: u32,
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(ENVELOPE_FIELDS)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(0)
        .and_then(|e| e.u8(PROTOCOL_VERSION))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(1)
        .and_then(|e| e.u8(1))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(2)
        .and_then(|e| e.bytes(&routing_tag))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(3)
        .and_then(|e| e.bytes(&message_id))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(4)
        .and_then(|e| e.u8(olm_type))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(5)
        .and_then(|e| e.bytes(payload))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(6)
        .and_then(|e| e.u16(part_number))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(7)
        .and_then(|e| e.u16(total_parts))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    encoder
        .u8(8)
        .and_then(|e| e.u32(capabilities))
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    Ok(encoder.into_writer())
}

/// Strictly parse one textual transport part.
pub fn decode_transport_part(text: &str) -> Result<EnvelopePart> {
    if text.len() > MAX_ENCODED_PART_BYTES || !text.starts_with(PREFIX) {
        return Err(ErrorCode::InvalidInput.into());
    }
    let encoded = &text[PREFIX.len()..];
    if encoded.is_empty()
        || encoded
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-' && *byte != b'_')
    {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    let binary = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    decode_part_binary(&binary)
}

fn decode_part_binary(binary: &[u8]) -> Result<EnvelopePart> {
    let mut decoder = Decoder::new(binary);
    let fields = read_canonical_map_len(&mut decoder, binary)?;
    if fields > MAX_MAP_FIELDS {
        return Err(ErrorCode::SizeLimit.into());
    }

    let mut seen = Vec::with_capacity(
        usize::try_from(fields).map_err(|_| CoreError::new(ErrorCode::SizeLimit))?,
    );
    let mut version = None;
    let mut message_type = None;
    let mut routing_tag = None;
    let mut message_id = None;
    let mut olm_type = None;
    let mut payload = None;
    let mut part_number = None;
    let mut total_parts = None;
    let mut capabilities = None;
    let mut previous_field = None;

    for _ in 0..fields {
        let field = read_canonical_unsigned(&mut decoder, binary)?;
        if seen.contains(&field) {
            return Err(ErrorCode::DuplicateField.into());
        }
        // Deterministic CBOR orders unsigned integer keys numerically: their
        // canonical encodings grow by length and then lexicographically.
        if previous_field.is_some_and(|previous| field < previous) {
            return Err(ErrorCode::InvalidEncoding.into());
        }
        seen.push(field);
        previous_field = Some(field);
        match field {
            0 => version = Some(read_canonical_u8(&mut decoder, binary)?),
            1 => message_type = Some(read_canonical_u8(&mut decoder, binary)?),
            2 => routing_tag = Some(read_fixed::<16>(&mut decoder, binary)?),
            3 => message_id = Some(read_fixed::<16>(&mut decoder, binary)?),
            4 => olm_type = Some(read_canonical_u8(&mut decoder, binary)?),
            5 => {
                let bytes = read_canonical_bytes(&mut decoder, binary)?;
                if bytes.len() > MAX_MESSAGE_BYTES {
                    return Err(ErrorCode::SizeLimit.into());
                }
                payload = Some(bytes.to_vec());
            }
            6 => part_number = Some(read_canonical_u16(&mut decoder, binary)?),
            7 => total_parts = Some(read_canonical_u16(&mut decoder, binary)?),
            8 => capabilities = Some(read_canonical_u32(&mut decoder, binary)?),
            OPTIONAL_FIELD_START.. => skip_bounded_optional(&mut decoder, binary)?,
            _ => return Err(ErrorCode::UnknownMandatoryField.into()),
        }
    }
    if decoder.position() != binary.len() {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    if version.ok_or(ErrorCode::MissingField)? != PROTOCOL_VERSION {
        return Err(ErrorCode::UnsupportedVersion.into());
    }
    if message_type.ok_or(ErrorCode::MissingField)? != 1 {
        return Err(ErrorCode::InvalidInput.into());
    }
    let olm_type = olm_type.ok_or(ErrorCode::MissingField)?;
    let part_number = part_number.ok_or(ErrorCode::MissingField)?;
    let total_parts = total_parts.ok_or(ErrorCode::MissingField)?;
    if olm_type > 1
        || total_parts == 0
        || total_parts > MAX_PARTS
        || part_number == 0
        || part_number > total_parts
    {
        return Err(ErrorCode::InvalidInput.into());
    }
    Ok(EnvelopePart {
        routing_tag: routing_tag.ok_or(ErrorCode::MissingField)?,
        message_id: message_id.ok_or(ErrorCode::MissingField)?,
        olm_type,
        payload: payload.ok_or(ErrorCode::MissingField)?,
        part_number,
        total_parts,
        capabilities: capabilities.ok_or(ErrorCode::MissingField)?,
    })
}

fn ensure_canonical(binary: &[u8], start: usize, end: usize, canonical: &[u8]) -> Result<()> {
    if binary.get(start..end) != Some(canonical) {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    Ok(())
}

fn read_canonical_map_len(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<u64> {
    let start = decoder.position();
    let fields = decoder
        .map()
        .map_err(|_| ErrorCode::InvalidEncoding)?
        .ok_or_else(|| CoreError::new(ErrorCode::InvalidEncoding))?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(fields)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    ensure_canonical(binary, start, decoder.position(), &encoder.into_writer())?;
    Ok(fields)
}

fn read_canonical_unsigned(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<u64> {
    let start = decoder.position();
    let value = decoder.u64().map_err(|_| ErrorCode::InvalidEncoding)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.u64(value).map_err(|_| ErrorCode::InvalidEncoding)?;
    ensure_canonical(binary, start, decoder.position(), &encoder.into_writer())?;
    Ok(value)
}

fn read_canonical_u8(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<u8> {
    u8::try_from(read_canonical_unsigned(decoder, binary)?)
        .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))
}

fn read_canonical_u16(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<u16> {
    u16::try_from(read_canonical_unsigned(decoder, binary)?)
        .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))
}

fn read_canonical_u32(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<u32> {
    u32::try_from(read_canonical_unsigned(decoder, binary)?)
        .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))
}

fn read_canonical_int(decoder: &mut Decoder<'_>, binary: &[u8]) -> Result<()> {
    let start = decoder.position();
    let value = decoder.int().map_err(|_| ErrorCode::InvalidEncoding)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.int(value).map_err(|_| ErrorCode::InvalidEncoding)?;
    ensure_canonical(binary, start, decoder.position(), &encoder.into_writer())
}

fn read_canonical_bytes<'a>(decoder: &mut Decoder<'a>, binary: &'a [u8]) -> Result<&'a [u8]> {
    let start = decoder.position();
    let value = decoder.bytes().map_err(|_| ErrorCode::InvalidEncoding)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .bytes(value)
        .map_err(|_| ErrorCode::InvalidEncoding)?;
    ensure_canonical(binary, start, decoder.position(), &encoder.into_writer())?;
    Ok(value)
}

fn read_canonical_str<'a>(decoder: &mut Decoder<'a>, binary: &'a [u8]) -> Result<&'a str> {
    let start = decoder.position();
    let value = decoder.str().map_err(|_| ErrorCode::InvalidEncoding)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.str(value).map_err(|_| ErrorCode::InvalidEncoding)?;
    ensure_canonical(binary, start, decoder.position(), &encoder.into_writer())?;
    Ok(value)
}

fn read_fixed<'a, const N: usize>(decoder: &mut Decoder<'a>, binary: &'a [u8]) -> Result<[u8; N]> {
    let bytes = read_canonical_bytes(decoder, binary)?;
    bytes.try_into().map_err(|_| ErrorCode::InvalidInput.into())
}

fn skip_bounded_optional<'a>(decoder: &mut Decoder<'a>, binary: &'a [u8]) -> Result<()> {
    match decoder.datatype().map_err(|_| ErrorCode::InvalidEncoding)? {
        Type::Bool => {
            decoder.bool().map_err(|_| ErrorCode::InvalidEncoding)?;
        }
        Type::Null => {
            decoder.null().map_err(|_| ErrorCode::InvalidEncoding)?;
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            read_canonical_unsigned(decoder, binary)?;
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::Int => {
            read_canonical_int(decoder, binary)?;
        }
        Type::Bytes => {
            if read_canonical_bytes(decoder, binary)?.len() > MAX_OPTIONAL_VALUE_BYTES {
                return Err(ErrorCode::SizeLimit.into());
            }
        }
        Type::String => {
            if read_canonical_str(decoder, binary)?.len() > MAX_OPTIONAL_VALUE_BYTES {
                return Err(ErrorCode::SizeLimit.into());
            }
        }
        _ => return Err(ErrorCode::InvalidEncoding.into()),
    }
    Ok(())
}

/// Reassemble parts in any order while rejecting duplicates and mixed messages.
pub fn reassemble_transport_parts<'a, I>(
    parts: I,
    expected_tag: &[u8; 16],
) -> Result<ReassembledMessage>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut decoded_by_number = BTreeMap::new();
    let mut expected_metadata: Option<([u8; 16], u8, u16, u32)> = None;
    let mut total_bytes = 0_usize;

    for text in parts {
        let part = decode_transport_part(text)?;
        if &part.routing_tag != expected_tag {
            return Err(ErrorCode::WrongContact.into());
        }
        let metadata = (
            part.message_id,
            part.olm_type,
            part.total_parts,
            part.capabilities,
        );
        if expected_metadata.is_some_and(|expected| expected != metadata) {
            return Err(ErrorCode::InconsistentParts.into());
        }
        expected_metadata = Some(metadata);
        total_bytes = total_bytes
            .checked_add(part.payload.len())
            .ok_or(ErrorCode::SizeLimit)?;
        if total_bytes > MAX_MESSAGE_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        if decoded_by_number
            .insert(part.part_number, part.payload)
            .is_some()
        {
            return Err(ErrorCode::Replay.into());
        }
    }

    let (message_id, olm_type, total_parts, capabilities) =
        expected_metadata.ok_or(ErrorCode::MissingPart)?;
    if decoded_by_number.len() != usize::from(total_parts)
        || (1..=total_parts).any(|number| !decoded_by_number.contains_key(&number))
    {
        return Err(ErrorCode::MissingPart.into());
    }
    let mut payload = Vec::with_capacity(total_bytes);
    for (_, chunk) in decoded_by_number {
        payload.extend_from_slice(&chunk);
    }
    Ok(ReassembledMessage {
        routing_tag: *expected_tag,
        message_id,
        olm_type,
        payload,
        capabilities,
    })
}
