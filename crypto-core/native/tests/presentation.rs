use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
};

use cipherboard_crypto::{
    decode_presentation, encode_presentation, encode_transport_parts, ErrorCode, TransportMode,
    TransportPresentation, MAX_PRESENTATION_TEXT_BYTES, MAX_PRESENTATION_WORDS,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const ENGLISH_BYTES: &[u8] = include_bytes!("../data/words_en_v1.txt");
const RUSSIAN_BYTES: &[u8] = include_bytes!("../data/words_ru_v1.txt");
const ENGLISH_TEXT: &str = include_str!("../data/words_en_v1.txt");
const RUSSIAN_TEXT: &str = include_str!("../data/words_ru_v1.txt");
const TAG_DOMAIN: &[u8] = b"CipherBoard Word Transport v1\0";
const TAG_BYTES: usize = 8;
const HEADER_BYTES: usize = 20;
const ENGLISH_BLOCKED_EXACT: &[&str] = &[
    "cocaine",
    "dead",
    "deadlier",
    "deadliest",
    "deadly",
    "death",
    "deaths",
    "heroin",
];
const ENGLISH_BLOCKED_FRAGMENTS: &[&str] = &[
    "bitch",
    "blood",
    "blowjob",
    "bomb",
    "bullshit",
    "cock",
    "corpse",
    "cunt",
    "dick",
    "dildo",
    "fuck",
    "hentai",
    "hostage",
    "masturbat",
    "motherfuck",
    "nigga",
    "nigger",
    "nipple",
    "penis",
    "porn",
    "prostitut",
    "pussy",
    "shit",
    "shoot",
    "terror",
    "vagina",
    "weapon",
];
const RUSSIAN_BLOCKED_EXACT: &[&str] = &[
    "войн",
    "война",
    "войне",
    "войной",
    "войною",
    "войну",
    "войны",
    "войнах",
    "войнами",
    "кровь",
    "крови",
    "кровью",
];
const RUSSIAN_BLOCKED_FRAGMENTS: &[&str] = &[
    "бляд",
    "блят",
    "бомб",
    "выстрел",
    "гандон",
    "гитлер",
    "дроч",
    "ебан",
    "ебат",
    "ебл",
    "жоп",
    "заложник",
    "кровав",
    "кровопролит",
    "кровотеч",
    "мертв",
    "насил",
    "наркот",
    "ниггер",
    "оргаз",
    "оруж",
    "педик",
    "пизд",
    "порно",
    "секс",
    "сись",
    "смерт",
    "солдат",
    "сперм",
    "стреля",
    "суицид",
    "сукин",
    "террор",
    "трах",
    "труп",
    "убив",
    "убий",
    "фашист",
    "хуев",
    "хуе",
    "хуй",
    "хуя",
    "член",
    "мудак",
];

#[test]
fn committed_dictionaries_have_pinned_bytes_and_invariants() {
    assert_eq!(
        digest_hex(ENGLISH_BYTES),
        "620b96da9c31f8552a6ed8eb54ef22a9a9a6b7885d2caf4ba9f658b748cf0cb3"
    );
    assert_eq!(
        digest_hex(RUSSIAN_BYTES),
        "6163eddf094c8c426959c1bb36d95dca3d7cbe4bdecc13bd13077279b7ccc8a9"
    );

    let english = words(ENGLISH_TEXT);
    let russian = words(RUSSIAN_TEXT);
    assert_dictionary(&english, |character| character.is_ascii_lowercase());
    assert_dictionary(&russian, |character| matches!(character, 'а'..='я'));
    assert_no_blocked_content(&english, ENGLISH_BLOCKED_EXACT, ENGLISH_BLOCKED_FRAGMENTS);
    assert_no_blocked_content(&russian, RUSSIAN_BLOCKED_EXACT, RUSSIAN_BLOCKED_FRAGMENTS);
    assert!(russian.contains(&"кровать"));
    assert!(russian.contains(&"кровати"));

    assert_eq!(
        sample(&english),
        [
            "that",
            "what",
            "this",
            "were",
            "house",
            "takes",
            "sold",
            "thoughts",
            "chicago",
            "mysterious",
            "messing",
            "forbidden",
            "protest",
        ]
    );
    assert_eq!(
        sample(&russian),
        [
            "меня",
            "тебя",
            "если",
            "думаю",
            "место",
            "готовы",
            "сделаешь",
            "радио",
            "любого",
            "напротив",
            "подряд",
            "отдала",
            "бегите",
        ]
    );

    for blocked in [
        "fuck", "shit", "bitch", "cunt", "dick", "cock", "pussy", "porn", "rape", "slut", "nigger",
        "faggot", "murder", "suicide", "nazi",
    ] {
        assert!(
            !english.contains(&blocked),
            "blocked English word: {blocked}"
        );
    }
    for blocked in [
        "блядь",
        "блять",
        "хуй",
        "пизда",
        "секс",
        "член",
        "мудак",
        "порно",
        "насилие",
        "ниггер",
        "фашист",
        "убийство",
    ] {
        assert!(
            !russian.contains(&blocked),
            "blocked Russian word: {blocked}"
        );
    }
}

#[test]
fn compact_and_both_word_alphabets_round_trip_exact_ordered_parts() {
    let parts = sample_parts(&vec![0x5a; 20 * 1024], TransportMode::Universal);
    assert!(parts.len() > 1);
    for presentation in [
        TransportPresentation::Compact,
        TransportPresentation::RussianWords,
        TransportPresentation::EnglishWords,
    ] {
        let encoded = encode_presentation(&parts, presentation).expect("encode presentation");
        let decoded = decode_presentation(&encoded).expect("decode presentation");
        assert_eq!(decoded.presentation(), presentation);
        assert_eq!(decoded.parts(), parts);
    }
}

#[test]
fn old_sms_sized_parts_remain_compatible_with_every_presentation() {
    let parts = sample_parts(&vec![0x2a; 512], TransportMode::SmsCompact);
    assert!(parts.len() > 1);
    for presentation in [
        TransportPresentation::Compact,
        TransportPresentation::RussianWords,
        TransportPresentation::EnglishWords,
    ] {
        let encoded = encode_presentation(&parts, presentation).expect("encode");
        assert_eq!(
            decode_presentation(&encoded).expect("decode").parts(),
            parts
        );
    }
}

#[test]
fn compact_decoder_restores_reordered_universal_and_legacy_sms_parts() {
    for mode in [TransportMode::Universal, TransportMode::SmsCompact] {
        let payload_bytes = if mode == TransportMode::Universal {
            20 * 1024
        } else {
            512
        };
        let parts = sample_parts(&vec![0x6b; payload_bytes], mode);
        assert!(parts.len() > 1);
        let mut reversed = parts.clone();
        reversed.reverse();
        let decoded = decode_presentation(&reversed.join("\n")).expect("reordered compact");
        assert_eq!(decoded.presentation(), TransportPresentation::Compact);
        assert_eq!(decoded.parts(), parts);
    }
}

#[test]
fn tag_first_makes_the_initial_words_change_with_ciphertext() {
    let first = encode_presentation(
        &sample_parts(b"first", TransportMode::Universal),
        TransportPresentation::EnglishWords,
    )
    .expect("first");
    let second = encode_presentation(
        &sample_parts(b"second", TransportMode::Universal),
        TransportPresentation::EnglishWords,
    )
    .expect("second");
    assert_ne!(
        first.split(' ').take(5).collect::<Vec<_>>(),
        second.split(' ').take(5).collect::<Vec<_>>()
    );
}

#[test]
fn word_decoder_accepts_only_the_documented_transport_whitespace() {
    let parts = sample_parts(b"whitespace", TransportMode::Universal);
    let encoded = encode_presentation(&parts, TransportPresentation::RussianWords).expect("encode");
    let separators = [" ", "\n", "\r", "\t", "\u{000c}"];
    let mut reformatted = String::from(" \n");
    for (index, token) in encoded.split(' ').enumerate() {
        if index > 0 {
            reformatted.push_str(separators[index % separators.len()]);
        }
        reformatted.push_str(token);
    }
    reformatted.push_str("\r\n");
    assert_eq!(
        decode_presentation(&reformatted)
            .expect("whitespace")
            .parts(),
        parts
    );

    for invalid in [
        encoded.replacen(' ', "\u{00a0}", 1),
        encoded.replacen(' ', "\u{200b}", 1),
        format!("{encoded}."),
    ] {
        assert_invalid(&invalid, ErrorCode::InvalidEncoding);
    }
}

#[test]
fn unknown_mixed_case_changed_and_fuzzy_words_fail_closed() {
    let parts = sample_parts(b"strict words", TransportMode::Universal);
    let encoded = encode_presentation(&parts, TransportPresentation::EnglishWords).expect("encode");
    let tokens: Vec<_> = encoded.split(' ').collect();
    let russian = words(RUSSIAN_TEXT);

    assert_invalid(
        &replace_token(&tokens, 0, "zzzzzzzzzz"),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        &replace_token(&tokens, 0, &tokens[0].to_uppercase()),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        &replace_token(&tokens, 1, russian[0]),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        &replace_token(&tokens, 0, &format!("{}\u{200d}", tokens[0])),
        ErrorCode::InvalidEncoding,
    );

    let english = words(ENGLISH_TEXT);
    let indices = word_indices(&english);
    let first_value = indices[tokens[0]];
    let changed = english[(usize::from(first_value) + 1) % english.len()];
    assert_invalid(
        &replace_token(&tokens, 0, changed),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        &tokens[..tokens.len() - 1].join(" "),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        &format!("{encoded} {}", english[0]),
        ErrorCode::InvalidEncoding,
    );
    assert_invalid(
        "these ordinary words are not ciphertext",
        ErrorCode::InvalidEncoding,
    );
}

#[test]
fn canonical_padding_rejects_nonzero_unused_bits() {
    let english = words(ENGLISH_TEXT);
    let indices = word_indices(&english);
    let mut covered = HashSet::new();
    for payload_length in 0..64 {
        let parts = sample_parts(&vec![0x44; payload_length], TransportMode::Universal);
        let encoded =
            encode_presentation(&parts, TransportPresentation::EnglishWords).expect("encode");
        let wrapper = unpack_words(&encoded, &indices);
        let body_length = u32::from_be_bytes(wrapper[16..20].try_into().expect("body length"));
        let expected = HEADER_BYTES + usize::try_from(body_length).expect("usize");
        let remainder = expected % 3;
        if remainder == 0 || !covered.insert(remainder) {
            continue;
        }
        let mut tokens: Vec<_> = encoded.split(' ').collect();
        let last = tokens.len() - 1;
        let value = indices[tokens[last]];
        assert_eq!(value & if remainder == 1 { 0x000f } else { 0x00ff }, 0);
        tokens[last] = english[usize::from(value | 1)];
        assert_invalid(&tokens.join(" "), ErrorCode::InvalidEncoding);
    }
    assert_eq!(covered, HashSet::from([1, 2]));
}

#[test]
fn strict_header_length_checksum_and_inner_envelope_validation() {
    let parts = sample_parts(b"header", TransportMode::Universal);
    let encoded = encode_presentation(&parts, TransportPresentation::EnglishWords).expect("encode");
    let english = words(ENGLISH_TEXT);
    let indices = word_indices(&english);

    assert_mutated(
        &encoded,
        &english,
        &indices,
        false,
        |wrapper| wrapper[0] ^= 1,
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[8] ^= 1,
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[11] = 2,
        ErrorCode::UnsupportedVersion,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[12] = 1,
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[13] = 1,
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[14..16].copy_from_slice(&0_u16.to_be_bytes()),
        ErrorCode::TooManyParts,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[14..16].copy_from_slice(&129_u16.to_be_bytes()),
        ErrorCode::TooManyParts,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[16..20].copy_from_slice(&0_u32.to_be_bytes()),
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[20..24].copy_from_slice(&0_u32.to_be_bytes()),
        ErrorCode::InvalidEncoding,
    );
    assert_mutated(
        &encoded,
        &english,
        &indices,
        true,
        |wrapper| wrapper[24] ^= 1,
        ErrorCode::InvalidEncoding,
    );
}

#[test]
fn ordering_and_size_bounds_are_enforced_before_output() {
    let parts = sample_parts(&vec![0x33; 20 * 1024], TransportMode::Universal);
    let mut reversed = parts.clone();
    reversed.reverse();
    assert_eq!(
        encode_presentation(&reversed, TransportPresentation::EnglishWords)
            .expect_err("order")
            .code(),
        ErrorCode::InconsistentParts
    );

    let oversized = sample_parts(&vec![0x55; 64 * 1024], TransportMode::Universal);
    assert_eq!(
        encode_presentation(&oversized, TransportPresentation::RussianWords)
            .expect_err("word limit")
            .code(),
        ErrorCode::SizeLimit
    );

    let too_many_words = std::iter::repeat_n("that", MAX_PRESENTATION_WORDS + 1)
        .collect::<Vec<_>>()
        .join(" ");
    assert_invalid(&too_many_words, ErrorCode::SizeLimit);
    assert_eq!(
        decode_presentation(&"a".repeat(MAX_PRESENTATION_TEXT_BYTES + 1))
            .err()
            .expect("text limit")
            .code(),
        ErrorCode::SizeLimit
    );
}

#[test]
fn golden_presentations_are_stable() {
    let parts = encode_transport_parts(
        [0x11; 16],
        [0x22; 16],
        1,
        b"word presentation golden",
        0x1234,
        TransportMode::Universal,
    )
    .expect("envelope");
    let english =
        encode_presentation(&parts, TransportPresentation::EnglishWords).expect("English");
    let russian =
        encode_presentation(&parts, TransportPresentation::RussianWords).expect("Russian");
    assert_eq!(
        digest_hex(english.as_bytes()),
        "a5a03f01a9df14b76cadf22302d42745bc59d0aec35425325b930b69cb8d9dec"
    );
    assert_eq!(
        digest_hex(russian.as_bytes()),
        "e4dcbf07c37440d7560c11d83ef02a1e95b7af3596446101ceba391c1bc0881a"
    );
    assert_eq!(
        decode_presentation(&english)
            .expect("English decode")
            .parts(),
        parts
    );
    assert_eq!(
        decode_presentation(&russian)
            .expect("Russian decode")
            .parts(),
        parts
    );
}

proptest! {
    #[test]
    fn arbitrary_utf8_presentation_never_panics(input in any::<String>()) {
        let _ = decode_presentation(&input);
    }

    #[test]
    fn valid_envelopes_round_trip_in_both_word_alphabets(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let parts = sample_parts(&payload, TransportMode::Universal);
        for presentation in [TransportPresentation::EnglishWords, TransportPresentation::RussianWords] {
            let text = encode_presentation(&parts, presentation).expect("encode");
            let decoded = decode_presentation(&text).expect("decode");
            prop_assert_eq!(decoded.parts(), parts.as_slice());
        }
    }
}

fn sample_parts(payload: &[u8], mode: TransportMode) -> Vec<String> {
    encode_transport_parts([0x42; 16], [0x24; 16], 1, payload, 7, mode).expect("sample envelope")
}

fn words(source: &'static str) -> Vec<&'static str> {
    source.lines().collect()
}

fn word_indices(dictionary: &[&'static str]) -> HashMap<&'static str, u16> {
    dictionary
        .iter()
        .enumerate()
        .map(|(index, word)| (*word, u16::try_from(index).expect("index")))
        .collect()
}

fn assert_dictionary(dictionary: &[&str], accepts: impl Fn(char) -> bool) {
    assert_eq!(dictionary.len(), 4096);
    assert_eq!(
        dictionary.iter().copied().collect::<HashSet<_>>().len(),
        4096
    );
    assert!(dictionary
        .iter()
        .all(|word| { (4..=10).contains(&word.chars().count()) && word.chars().all(&accepts) }));
}

fn assert_no_blocked_content(dictionary: &[&str], exact: &[&str], fragments: &[&str]) {
    for word in dictionary {
        assert!(
            !exact.contains(word),
            "blocked exact dictionary word: {word}"
        );
        for fragment in fragments {
            assert!(
                !word.contains(fragment),
                "blocked dictionary fragment {fragment:?} in {word:?}"
            );
        }
    }
}

fn sample(dictionary: &[&'static str]) -> [&'static str; 13] {
    [
        0, 1, 2, 31, 127, 511, 1023, 1535, 2047, 2559, 3071, 3583, 4095,
    ]
    .map(|index| dictionary[index])
}

fn replace_token(tokens: &[&str], index: usize, replacement: &str) -> String {
    tokens
        .iter()
        .enumerate()
        .map(|(candidate, token)| {
            if candidate == index {
                replacement
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn assert_invalid(text: &str, expected: ErrorCode) {
    assert_eq!(
        decode_presentation(text).err().expect("must fail").code(),
        expected
    );
}

fn assert_mutated(
    encoded: &str,
    dictionary: &[&'static str],
    indices: &HashMap<&'static str, u16>,
    refresh_checksum: bool,
    mutate: impl FnOnce(&mut Vec<u8>),
    expected: ErrorCode,
) {
    let mut wrapper = unpack_words(encoded, indices);
    let body_length = usize::try_from(u32::from_be_bytes(
        wrapper[16..20].try_into().expect("length"),
    ))
    .expect("usize");
    wrapper.truncate(HEADER_BYTES + body_length);
    mutate(&mut wrapper);
    if refresh_checksum {
        refresh_tag(&mut wrapper);
    }
    assert_invalid(&pack_words(&wrapper, dictionary), expected);
}

fn unpack_words(encoded: &str, indices: &HashMap<&'static str, u16>) -> Vec<u8> {
    let mut output = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_usize;
    for token in encoded.split(' ') {
        accumulator = (accumulator << 12) | u32::from(indices[token]);
        bits += 12;
        while bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((accumulator >> bits) & 0xff).expect("byte"));
            accumulator &= if bits == 0 { 0 } else { (1_u32 << bits) - 1 };
        }
    }
    output
}

fn pack_words(wrapper: &[u8], dictionary: &[&str]) -> String {
    let mut words = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_usize;
    for byte in wrapper {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 12 {
            bits -= 12;
            words.push(dictionary[usize::try_from((accumulator >> bits) & 0x0fff).expect("index")]);
            accumulator &= if bits == 0 { 0 } else { (1_u32 << bits) - 1 };
        }
    }
    if bits > 0 {
        words.push(dictionary[usize::try_from(accumulator << (12 - bits)).expect("index")]);
    }
    words.join(" ")
}

fn refresh_tag(wrapper: &mut [u8]) {
    let mut digest = Sha256::new();
    digest.update(TAG_DOMAIN);
    digest.update(&wrapper[TAG_BYTES..]);
    let digest = digest.finalize();
    wrapper[..TAG_BYTES].copy_from_slice(&digest[..TAG_BYTES]);
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}
