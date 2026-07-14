use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::{
    decode_transport_part, CoreError, ErrorCode, Result, MAX_ENCODED_PART_BYTES, MAX_MESSAGE_BYTES,
    MAX_PARTS,
};

const COMPACT_PREFIX: &str = "CB1:";
const WORD_MAGIC: &[u8; 3] = b"CBW";
const WORD_VERSION: u8 = 1;
const WORD_FLAGS: u8 = 0;
const TAG_BYTES: usize = 8;
const HEADER_BYTES: usize = 20;
const PART_LENGTH_BYTES: usize = 4;
const WORD_BITS: usize = 12;
const WORD_VALUES: usize = 1 << WORD_BITS;
const TAG_DOMAIN: &[u8] = b"CipherBoard Word Transport v1\0";

/// Maximum decoded `CBW1` wrapper size. The resulting word string stays below
/// Android's bounded clipboard/selection input even with ten-letter Russian words.
pub const MAX_WORD_WRAPPER_BYTES: usize = 48 * 1024;
/// Maximum UTF-8 bytes accepted for either compact or word presentation text.
pub const MAX_PRESENTATION_TEXT_BYTES: usize = 768 * 1024;
/// Maximum words in a canonical v1 presentation.
pub const MAX_PRESENTATION_WORDS: usize = MAX_WORD_WRAPPER_BYTES * 8 / WORD_BITS;

const ENGLISH_SOURCE: &str = include_str!("../data/words_en_v1.txt");
const RUSSIAN_SOURCE: &str = include_str!("../data/words_ru_v1.txt");

static ENGLISH_DICTIONARY: OnceLock<Option<Dictionary>> = OnceLock::new();
static RUSSIAN_DICTIONARY: OnceLock<Option<Dictionary>> = OnceLock::new();

/// Non-cryptographic presentation applied after the authenticated envelope is built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportPresentation {
    Compact = 0,
    RussianWords = 1,
    EnglishWords = 2,
}

impl TransportPresentation {
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Compact),
            1 => Some(Self::RussianWords),
            2 => Some(Self::EnglishWords),
            _ => None,
        }
    }

    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    const fn alphabet(self) -> Option<WordAlphabet> {
        match self {
            Self::Compact => None,
            Self::RussianWords => Some(WordAlphabet::Russian),
            Self::EnglishWords => Some(WordAlphabet::English),
        }
    }
}

/// A fully validated transport presentation and its canonical `CB1:` parts.
pub struct DecodedPresentation {
    presentation: TransportPresentation,
    parts: Vec<String>,
}

impl DecodedPresentation {
    pub const fn presentation(&self) -> TransportPresentation {
        self.presentation
    }

    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    pub fn into_parts(self) -> Vec<String> {
        self.parts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum WordAlphabet {
    Russian = 1,
    English = 2,
}

impl WordAlphabet {
    const fn presentation(self) -> TransportPresentation {
        match self {
            Self::Russian => TransportPresentation::RussianWords,
            Self::English => TransportPresentation::EnglishWords,
        }
    }

    const fn accepts(self, character: char) -> bool {
        match self {
            Self::Russian => matches!(character, 'а'..='я'),
            Self::English => character.is_ascii_lowercase(),
        }
    }

    fn dictionary(self) -> Result<&'static Dictionary> {
        let value = match self {
            Self::Russian => {
                RUSSIAN_DICTIONARY.get_or_init(|| Dictionary::new(RUSSIAN_SOURCE, self))
            }
            Self::English => {
                ENGLISH_DICTIONARY.get_or_init(|| Dictionary::new(ENGLISH_SOURCE, self))
            }
        };
        value
            .as_ref()
            .ok_or_else(|| CoreError::new(ErrorCode::InvalidState))
    }
}

struct Dictionary {
    words: Vec<&'static str>,
    indices: HashMap<&'static str, u16>,
}

impl Dictionary {
    fn new(source: &'static str, alphabet: WordAlphabet) -> Option<Self> {
        let words: Vec<_> = source.lines().collect();
        if words.len() != WORD_VALUES {
            return None;
        }
        let mut unique = HashSet::with_capacity(WORD_VALUES);
        if words.iter().any(|word| {
            !(4..=10).contains(&word.chars().count())
                || !word.chars().all(|character| alphabet.accepts(character))
                || !unique.insert(*word)
        }) {
            return None;
        }
        let indices = words
            .iter()
            .enumerate()
            .map(|(index, word)| u16::try_from(index).ok().map(|value| (*word, value)))
            .collect::<Option<HashMap<_, _>>>()?;
        Some(Self { words, indices })
    }

    fn word(&self, value: u16) -> Option<&'static str> {
        self.words.get(usize::from(value)).copied()
    }

    fn value(&self, word: &str) -> Option<u16> {
        self.indices.get(word).copied()
    }
}

/// Validate and render canonical envelope parts in the selected presentation.
pub fn encode_presentation(
    parts: &[String],
    presentation: TransportPresentation,
) -> Result<String> {
    validate_ordered_parts(parts)?;
    match presentation.alphabet() {
        None => encode_compact(parts),
        Some(alphabet) => encode_words(parts, alphabet),
    }
}

/// Auto-detect compact, Russian-word, or English-word transport and recover
/// the exact ordered canonical `CB1:` parts.
pub fn decode_presentation(text: &str) -> Result<DecodedPresentation> {
    if text.is_empty() || text.len() > MAX_PRESENTATION_TEXT_BYTES {
        return Err(ErrorCode::SizeLimit.into());
    }
    let first = text
        .split(is_transport_whitespace)
        .find(|token| !token.is_empty())
        .ok_or(ErrorCode::InvalidInput)?;
    if first.starts_with(COMPACT_PREFIX) {
        let parts = decode_compact(text)?;
        return Ok(DecodedPresentation {
            presentation: TransportPresentation::Compact,
            parts,
        });
    }
    let alphabet = detect_alphabet(first)?;
    let parts = decode_words(text, alphabet)?;
    Ok(DecodedPresentation {
        presentation: alphabet.presentation(),
        parts,
    })
}

fn encode_compact(parts: &[String]) -> Result<String> {
    let length = parts
        .iter()
        .try_fold(parts.len().saturating_sub(1), |total, part| {
            total.checked_add(part.len())
        })
        .ok_or(ErrorCode::SizeLimit)?;
    if length > MAX_PRESENTATION_TEXT_BYTES {
        return Err(ErrorCode::SizeLimit.into());
    }
    Ok(parts.join("\n"))
}

fn decode_compact(text: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    for token in text
        .split(is_transport_whitespace)
        .filter(|token| !token.is_empty())
    {
        if parts.len() == usize::from(MAX_PARTS) {
            return Err(ErrorCode::TooManyParts.into());
        }
        if token.len() > MAX_ENCODED_PART_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        parts.push(token.to_owned());
    }
    canonicalize_unordered_parts(parts)
}

fn canonicalize_unordered_parts(parts: Vec<String>) -> Result<Vec<String>> {
    if parts.is_empty() {
        return Err(ErrorCode::MissingPart.into());
    }

    let mut expected: Option<PartSetMetadata> = None;
    let mut payload_bytes = 0_usize;
    let mut numbered = Vec::with_capacity(parts.len());
    let mut seen = vec![false; usize::from(MAX_PARTS)];
    for text in parts {
        let part = decode_transport_part(&text)?;
        payload_bytes = payload_bytes
            .checked_add(part.payload().len())
            .filter(|total| *total <= MAX_MESSAGE_BYTES)
            .ok_or(ErrorCode::SizeLimit)?;
        let metadata = PartSetMetadata {
            routing_tag: *part.routing_tag(),
            message_id: *part.message_id(),
            olm_type: part.olm_type(),
            total_parts: part.total_parts(),
            capabilities: part.capabilities(),
        };
        if expected.is_some_and(|value| value != metadata) {
            return Err(ErrorCode::InconsistentParts.into());
        }
        expected = Some(metadata);

        let number = part.part_number();
        let index = usize::from(number - 1);
        if seen[index] {
            return Err(ErrorCode::Replay.into());
        }
        seen[index] = true;
        numbered.push((number, text));
    }

    let total_parts = expected.ok_or(ErrorCode::MissingPart)?.total_parts;
    if numbered.len() != usize::from(total_parts)
        || seen[..usize::from(total_parts)].iter().any(|value| !value)
    {
        return Err(ErrorCode::MissingPart.into());
    }
    numbered.sort_unstable_by_key(|(number, _)| *number);
    Ok(numbered.into_iter().map(|(_, text)| text).collect())
}

fn encode_words(parts: &[String], alphabet: WordAlphabet) -> Result<String> {
    let mut body = Vec::new();
    for part in parts {
        let encoded = part
            .strip_prefix(COMPACT_PREFIX)
            .ok_or(ErrorCode::InvalidInput)?;
        let binary = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
        let length = u32::try_from(binary.len()).map_err(|_| ErrorCode::SizeLimit)?;
        let prospective = body
            .len()
            .checked_add(PART_LENGTH_BYTES)
            .and_then(|value| value.checked_add(binary.len()))
            .ok_or(ErrorCode::SizeLimit)?;
        if HEADER_BYTES
            .checked_add(prospective)
            .is_none_or(|value| value > MAX_WORD_WRAPPER_BYTES)
        {
            return Err(ErrorCode::SizeLimit.into());
        }
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&binary);
    }

    let body_length = u32::try_from(body.len()).map_err(|_| ErrorCode::SizeLimit)?;
    let part_count = u16::try_from(parts.len()).map_err(|_| ErrorCode::TooManyParts)?;
    let mut wrapper = Vec::with_capacity(HEADER_BYTES + body.len());
    wrapper.resize(TAG_BYTES, 0);
    wrapper.extend_from_slice(WORD_MAGIC);
    wrapper.push(WORD_VERSION);
    wrapper.push(alphabet as u8);
    wrapper.push(WORD_FLAGS);
    wrapper.extend_from_slice(&part_count.to_be_bytes());
    wrapper.extend_from_slice(&body_length.to_be_bytes());
    wrapper.extend_from_slice(&body);
    let tag = presentation_tag(&wrapper[TAG_BYTES..]);
    wrapper[..TAG_BYTES].copy_from_slice(&tag);
    encode_base4096(&wrapper, alphabet)
}

fn decode_words(text: &str, detected_alphabet: WordAlphabet) -> Result<Vec<String>> {
    let dictionary = detected_alphabet.dictionary()?;
    let mut values = Vec::new();
    for token in text
        .split(is_transport_whitespace)
        .filter(|token| !token.is_empty())
    {
        if values.len() == MAX_PRESENTATION_WORDS {
            return Err(ErrorCode::SizeLimit.into());
        }
        values.push(dictionary.value(token).ok_or(ErrorCode::InvalidEncoding)?);
    }
    if values.is_empty() {
        return Err(ErrorCode::InvalidInput.into());
    }

    let (mut wrapper, remaining_value, remaining_bits) = decode_base4096(&values)?;
    if wrapper.len() < HEADER_BYTES
        || wrapper[TAG_BYTES..TAG_BYTES + WORD_MAGIC.len()] != *WORD_MAGIC
    {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    if wrapper[TAG_BYTES + WORD_MAGIC.len()] != WORD_VERSION {
        return Err(ErrorCode::UnsupportedVersion.into());
    }
    if wrapper[12] != detected_alphabet as u8 || wrapper[13] != WORD_FLAGS {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    let part_count = u16::from_be_bytes([wrapper[14], wrapper[15]]);
    if part_count == 0 || part_count > MAX_PARTS {
        return Err(ErrorCode::TooManyParts.into());
    }
    let body_length = usize::try_from(u32::from_be_bytes([
        wrapper[16],
        wrapper[17],
        wrapper[18],
        wrapper[19],
    ]))
    .map_err(|_| CoreError::new(ErrorCode::SizeLimit))?;
    let expected_length = HEADER_BYTES
        .checked_add(body_length)
        .filter(|length| *length <= MAX_WORD_WRAPPER_BYTES)
        .ok_or(ErrorCode::SizeLimit)?;
    let expected_words = expected_length
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(WORD_BITS - 1))
        .map(|bits| bits / WORD_BITS)
        .ok_or(ErrorCode::SizeLimit)?;
    if values.len() != expected_words
        || wrapper.len() < expected_length
        || wrapper[expected_length..].iter().any(|value| *value != 0)
        || remaining_bits > 0 && remaining_value != 0
    {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    wrapper.truncate(expected_length);
    if presentation_tag(&wrapper[TAG_BYTES..]) != wrapper[..TAG_BYTES] {
        return Err(ErrorCode::InvalidEncoding.into());
    }

    let mut offset = HEADER_BYTES;
    let mut parts = Vec::with_capacity(usize::from(part_count));
    for _ in 0..part_count {
        let length_end = offset
            .checked_add(PART_LENGTH_BYTES)
            .ok_or(ErrorCode::SizeLimit)?;
        let length_bytes: [u8; PART_LENGTH_BYTES] = wrapper
            .get(offset..length_end)
            .ok_or(ErrorCode::InvalidEncoding)?
            .try_into()
            .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
        let part_length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| CoreError::new(ErrorCode::SizeLimit))?;
        if part_length == 0 {
            return Err(ErrorCode::InvalidEncoding.into());
        }
        let part_end = length_end
            .checked_add(part_length)
            .ok_or(ErrorCode::SizeLimit)?;
        let binary = wrapper
            .get(length_end..part_end)
            .ok_or(ErrorCode::InvalidEncoding)?;
        let mut part = String::with_capacity(COMPACT_PREFIX.len() + binary.len().div_ceil(3) * 4);
        part.push_str(COMPACT_PREFIX);
        URL_SAFE_NO_PAD.encode_string(binary, &mut part);
        if part.len() > MAX_ENCODED_PART_BYTES {
            return Err(ErrorCode::SizeLimit.into());
        }
        parts.push(part);
        offset = part_end;
    }
    if offset != expected_length {
        return Err(ErrorCode::InvalidEncoding.into());
    }
    validate_ordered_parts(&parts)?;
    Ok(parts)
}

fn detect_alphabet(first_word: &str) -> Result<WordAlphabet> {
    let english = WordAlphabet::English
        .dictionary()?
        .value(first_word)
        .is_some();
    let russian = WordAlphabet::Russian
        .dictionary()?
        .value(first_word)
        .is_some();
    match (english, russian) {
        (true, false) => Ok(WordAlphabet::English),
        (false, true) => Ok(WordAlphabet::Russian),
        _ => Err(ErrorCode::InvalidEncoding.into()),
    }
}

fn encode_base4096(input: &[u8], alphabet: WordAlphabet) -> Result<String> {
    let dictionary = alphabet.dictionary()?;
    let word_count = input
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(WORD_BITS - 1))
        .map(|bits| bits / WORD_BITS)
        .ok_or(ErrorCode::SizeLimit)?;
    if word_count > MAX_PRESENTATION_WORDS {
        return Err(ErrorCode::SizeLimit.into());
    }

    let mut output = String::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_usize;
    let mut written = 0_usize;
    for byte in input {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= WORD_BITS {
            bits -= WORD_BITS;
            let value = u16::try_from((accumulator >> bits) & 0x0fff)
                .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
            push_word(&mut output, dictionary, value, &mut written)?;
            accumulator &= low_mask(bits);
        }
    }
    if bits > 0 {
        let value = u16::try_from((accumulator << (WORD_BITS - bits)) & 0x0fff)
            .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?;
        push_word(&mut output, dictionary, value, &mut written)?;
    }
    if written != word_count || output.len() > MAX_PRESENTATION_TEXT_BYTES {
        return Err(ErrorCode::SizeLimit.into());
    }
    Ok(output)
}

fn push_word(
    output: &mut String,
    dictionary: &Dictionary,
    value: u16,
    written: &mut usize,
) -> Result<()> {
    let word = dictionary.word(value).ok_or(ErrorCode::InvalidState)?;
    if *written > 0 {
        output.push(' ');
    }
    output.push_str(word);
    *written += 1;
    Ok(())
}

fn decode_base4096(values: &[u16]) -> Result<(Vec<u8>, u32, usize)> {
    let capacity = values
        .len()
        .checked_mul(WORD_BITS)
        .map(|bits| bits / 8)
        .ok_or(ErrorCode::SizeLimit)?;
    let mut output = Vec::with_capacity(capacity);
    let mut accumulator = 0_u32;
    let mut bits = 0_usize;
    for value in values {
        if usize::from(*value) >= WORD_VALUES {
            return Err(ErrorCode::InvalidEncoding.into());
        }
        accumulator = (accumulator << WORD_BITS) | u32::from(*value);
        bits += WORD_BITS;
        while bits >= 8 {
            bits -= 8;
            output.push(
                u8::try_from((accumulator >> bits) & 0xff)
                    .map_err(|_| CoreError::new(ErrorCode::InvalidEncoding))?,
            );
            accumulator &= low_mask(bits);
        }
    }
    Ok((output, accumulator, bits))
}

const fn low_mask(bits: usize) -> u32 {
    if bits == 0 {
        0
    } else {
        (1_u32 << bits) - 1
    }
}

fn presentation_tag(bytes: &[u8]) -> [u8; TAG_BYTES] {
    let mut digest = Sha256::new();
    digest.update(TAG_DOMAIN);
    digest.update(bytes);
    let digest = digest.finalize();
    let mut tag = [0_u8; TAG_BYTES];
    tag.copy_from_slice(&digest[..TAG_BYTES]);
    tag
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PartSetMetadata {
    routing_tag: [u8; 16],
    message_id: [u8; 16],
    olm_type: u8,
    total_parts: u16,
    capabilities: u32,
}

fn validate_ordered_parts(parts: &[String]) -> Result<()> {
    if parts.is_empty() {
        return Err(ErrorCode::MissingPart.into());
    }
    if parts.len() > usize::from(MAX_PARTS) {
        return Err(ErrorCode::TooManyParts.into());
    }

    let mut expected: Option<PartSetMetadata> = None;
    let mut payload_bytes = 0_usize;
    for (index, text) in parts.iter().enumerate() {
        let part = decode_transport_part(text)?;
        payload_bytes = payload_bytes
            .checked_add(part.payload().len())
            .filter(|total| *total <= MAX_MESSAGE_BYTES)
            .ok_or(ErrorCode::SizeLimit)?;
        let part_number = u16::try_from(index + 1).map_err(|_| ErrorCode::TooManyParts)?;
        let total_parts = u16::try_from(parts.len()).map_err(|_| ErrorCode::TooManyParts)?;
        if part.part_number() != part_number || part.total_parts() != total_parts {
            return Err(ErrorCode::InconsistentParts.into());
        }
        let metadata = PartSetMetadata {
            routing_tag: *part.routing_tag(),
            message_id: *part.message_id(),
            olm_type: part.olm_type(),
            total_parts: part.total_parts(),
            capabilities: part.capabilities(),
        };
        if expected.is_some_and(|value| value != metadata) {
            return Err(ErrorCode::InconsistentParts.into());
        }
        expected = Some(metadata);
    }
    Ok(())
}

const fn is_transport_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\n' | '\r' | '\t' | '\u{000c}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_bit_codec_has_canonical_padding_for_all_remainders() {
        for sample in [
            &[0x12_u8][..],
            &[0x12, 0x34],
            &[0x12, 0x34, 0x56],
            &[0x12, 0x34, 0x56, 0x78],
        ] {
            let text = encode_base4096(sample, WordAlphabet::English).expect("encode");
            let dictionary = WordAlphabet::English.dictionary().expect("dictionary");
            let values: Vec<_> = text
                .split(' ')
                .map(|word| dictionary.value(word).expect("word"))
                .collect();
            let (decoded, remaining, _) = decode_base4096(&values).expect("decode");
            assert_eq!(&decoded[..sample.len()], sample);
            assert!(decoded[sample.len()..].iter().all(|value| *value == 0));
            assert_eq!(remaining, 0);
        }
    }
}
