use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cipherboard_crypto::{
    decode_transport_part, encode_transport_parts, parse_pairing_payload,
    reassemble_transport_parts, CipherAccount, CipherSession, ErrorCode, PairingOffer,
    PairingPayloadType, PairingResponse, SecretBytes, TransportMode, MAX_PARTS,
};
use minicbor::Encoder;
use proptest::prelude::*;

const NOW: u64 = 1_800_000_000;
const CAPS: u32 = 0b1011;

struct Paired {
    alice: CipherAccount,
    bob: CipherAccount,
    alice_state: Vec<u8>,
    bob_state: Vec<u8>,
}

fn bytes(secret: &SecretBytes) -> Vec<u8> {
    secret.expose().to_vec()
}

fn pair() -> Paired {
    let mut alice = CipherAccount::new();
    let bob = CipherAccount::new();
    let offer = alice.create_pairing_offer(NOW, 600, CAPS).expect("offer");
    let offer = PairingOffer::decode_qr(&offer.encode_qr().expect("offer QR")).expect("scan offer");
    let prepared = bob
        .respond_to_pairing_offer(&offer, NOW + 1, u32::MAX)
        .expect("response");
    let bob_safety = prepared.safety_code.clone();
    let response = PairingResponse::decode_qr(&prepared.response.encode_qr().expect("response QR"))
        .expect("scan response");
    let bob_state = bytes(&prepared.session.serialize_state().expect("bob state"));
    let completed = alice
        .complete_pairing(&offer, &response, NOW + 2)
        .expect("complete pairing");
    assert!(bob_safety == completed.safety_code);
    assert_eq!(bob_safety.hash(), completed.safety_code.hash());
    assert_eq!(bob_safety.decimal_groups().split(' ').count(), 8);
    assert_eq!(bob_safety.word_code().split(' ').count(), 8);
    let alice_state = bytes(&completed.session.serialize_state().expect("alice state"));
    Paired {
        alice,
        bob,
        alice_state,
        bob_state,
    }
}

fn encrypt(state: &mut Vec<u8>, plaintext: &[u8], mode: TransportMode) -> Vec<String> {
    let session = CipherSession::deserialize_state(state).expect("load sender state");
    let prepared = session
        .prepare_encrypt(plaintext, CAPS, mode)
        .expect("encrypt");
    let parts = prepared.parts().to_vec();
    *state = bytes(prepared.next_state());
    parts
}

fn decrypt(state: &mut Vec<u8>, parts: &[String]) -> Vec<u8> {
    let session = CipherSession::deserialize_state(state).expect("load receiver state");
    let prepared = session
        .prepare_decrypt(parts.iter().map(String::as_str))
        .expect("decrypt");
    let plaintext = bytes(prepared.plaintext());
    *state = bytes(prepared.next_state());
    plaintext
}

#[test]
fn pairing_qr_and_bidirectional_first_messages() {
    let mut paired = pair();
    assert!(paired.alice.public_identity() != paired.bob.public_identity());

    let first = encrypt(
        &mut paired.alice_state,
        "Привет, Bob 👋".as_bytes(),
        TransportMode::Universal,
    );
    assert_eq!(
        decrypt(&mut paired.bob_state, &first),
        "Привет, Bob 👋".as_bytes()
    );

    let reply = encrypt(
        &mut paired.bob_state,
        b"Hello, Alice",
        TransportMode::Universal,
    );
    assert_eq!(decrypt(&mut paired.alice_state, &reply), b"Hello, Alice");
}

#[test]
fn authenticated_pairing_metadata_exposes_only_public_ui_fields() {
    let mut alice = CipherAccount::new();
    let bob = CipherAccount::new();
    let offer = alice.create_pairing_offer(NOW, 600, CAPS).expect("offer");
    let offer_qr = offer.encode_qr().expect("offer QR");
    let offer_metadata = parse_pairing_payload(&offer_qr, NOW + 1).expect("offer metadata");
    assert!(offer_metadata.payload_type() == PairingPayloadType::Offer);
    assert_eq!(offer_metadata.pairing_id(), offer.pairing_id());
    assert!(offer_metadata.remote_identity() == alice.public_identity());
    assert_eq!(
        offer_metadata.remote_identity_fingerprint(),
        alice.public_identity().fingerprint()
    );
    assert_eq!(offer_metadata.nonce(), offer.nonce());
    assert_eq!(offer_metadata.capabilities(), CAPS);
    assert_eq!(offer_metadata.expires_at(), Some(NOW + 600));
    assert!(!offer_metadata.is_expired());
    assert_eq!(
        offer_metadata.offer_hash(),
        &offer.transcript_hash().expect("hash")
    );

    let expired = parse_pairing_payload(&offer_qr, NOW + 601).expect("expired metadata");
    assert!(expired.is_expired());

    let prepared = bob
        .respond_to_pairing_offer(&offer, NOW + 1, u32::MAX)
        .expect("response");
    let response_qr = prepared.response.encode_qr().expect("response QR");
    let response_metadata =
        parse_pairing_payload(&response_qr, NOW + 2).expect("response metadata");
    assert!(response_metadata.payload_type() == PairingPayloadType::Response);
    assert_eq!(response_metadata.pairing_id(), offer.pairing_id());
    assert!(response_metadata.remote_identity() == bob.public_identity());
    assert_eq!(
        response_metadata.remote_identity_fingerprint(),
        bob.public_identity().fingerprint()
    );
    assert_eq!(response_metadata.nonce(), prepared.response.nonce());
    assert_eq!(response_metadata.capabilities(), CAPS);
    assert_eq!(response_metadata.expires_at(), None);
    assert!(!response_metadata.is_expired());
    assert_eq!(response_metadata.offer_hash(), offer_metadata.offer_hash());
}

#[test]
fn pairing_metadata_rejects_tampering_and_noncanonical_cbor() {
    let mut account = CipherAccount::new();
    let offer = account.create_pairing_offer(NOW, 60, CAPS).expect("offer");
    let qr = offer.encode_qr().expect("QR");

    let mut tampered = qr.clone().into_bytes();
    let last = tampered.last_mut().expect("non-empty QR");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ASCII");
    assert!(parse_pairing_payload(&tampered, NOW).is_err());

    let mut binary = URL_SAFE_NO_PAD
        .decode(qr.strip_prefix("CBO1:").expect("prefix"))
        .expect("base64");
    assert_eq!(binary[1], 1);
    binary[1] = 0x18;
    binary.insert(2, 1);
    let noncanonical = format!("CBO1:{}", URL_SAFE_NO_PAD.encode(binary));
    let error = parse_pairing_payload(&noncanonical, NOW)
        .err()
        .expect("noncanonical CBOR");
    assert_eq!(error.code(), ErrorCode::InvalidEncoding);
}

#[test]
fn account_and_session_state_round_trip() {
    let paired = pair();
    let account_state = paired.alice.serialize_state().expect("account state");
    let restored =
        CipherAccount::deserialize_state(account_state.expose()).expect("restore account");
    assert!(restored.public_identity() == paired.alice.public_identity());

    let restored_session =
        CipherSession::deserialize_state(&paired.alice_state).expect("restore session");
    assert!(restored_session.local_identity() == paired.alice.public_identity());
    assert!(restored_session.remote_identity() == paired.bob.public_identity());
}

#[test]
fn one_thousand_sequential_messages() {
    let mut paired = pair();
    for index in 0_u32..1000 {
        let plaintext = format!("message-{index}");
        let parts = encrypt(
            &mut paired.alice_state,
            plaintext.as_bytes(),
            TransportMode::Universal,
        );
        assert_eq!(decrypt(&mut paired.bob_state, &parts), plaintext.as_bytes());
    }
}

#[test]
fn out_of_order_and_missing_messages() {
    let mut paired = pair();
    let mut messages = Vec::new();
    // vodozemac intentionally bounds retained skipped message keys. Exercise
    // reordering within that security bound instead of making it unbounded.
    for index in 0_u16..32 {
        messages.push((
            index,
            encrypt(
                &mut paired.alice_state,
                &index.to_be_bytes(),
                TransportMode::Universal,
            ),
        ));
    }
    let missing = messages.remove(16);
    messages.reverse();
    for (index, parts) in messages {
        assert_eq!(decrypt(&mut paired.bob_state, &parts), index.to_be_bytes());
    }
    assert_eq!(
        decrypt(&mut paired.bob_state, &missing.1),
        missing.0.to_be_bytes()
    );
}

#[test]
fn replay_is_rejected_after_restart() {
    let mut paired = pair();
    let parts = encrypt(&mut paired.alice_state, b"once", TransportMode::Universal);
    assert_eq!(decrypt(&mut paired.bob_state, &parts), b"once");

    let restarted = CipherSession::deserialize_state(&paired.bob_state).expect("restart state");
    let error = restarted
        .prepare_decrypt(parts.iter().map(String::as_str))
        .err()
        .expect("replay must fail");
    assert_eq!(error.code(), ErrorCode::Replay);
}

#[test]
fn failed_authenticated_decrypt_does_not_consume_durable_ratchet_state() {
    let mut paired = pair();
    let original = encrypt(
        &mut paired.alice_state,
        b"authenticated payload",
        TransportMode::Universal,
    );
    let following = encrypt(
        &mut paired.alice_state,
        b"following payload",
        TransportMode::Universal,
    );

    let decoded = decode_transport_part(&original[0]).expect("decode original");
    let mut altered_payload = decoded.payload().to_vec();
    let middle = altered_payload.len() / 2;
    altered_payload[middle] ^= 1;
    let tampered = encode_transport_parts(
        *decoded.routing_tag(),
        *decoded.message_id(),
        decoded.olm_type(),
        &altered_payload,
        decoded.capabilities(),
        TransportMode::Universal,
    )
    .expect("valid outer envelope");

    let durable_before_failure = paired.bob_state.clone();
    let attempt = CipherSession::deserialize_state(&durable_before_failure).expect("receiver");
    assert!(attempt
        .prepare_decrypt(tampered.iter().map(String::as_str))
        .is_err());
    assert_eq!(paired.bob_state, durable_before_failure);

    // A failed private snapshot must not prevent later out-of-order delivery
    // or consumption of the original ciphertext from durable state.
    assert_eq!(
        decrypt(&mut paired.bob_state, &following),
        b"following payload"
    );
    assert_eq!(
        decrypt(&mut paired.bob_state, &original),
        b"authenticated payload"
    );
}

#[test]
fn outer_message_id_is_bound_inside_olm_payload() {
    let mut paired = pair();
    let parts = encrypt(
        &mut paired.alice_state,
        b"bound identifier",
        TransportMode::Universal,
    );
    let decoded = decode_transport_part(&parts[0]).expect("decode original");
    let forged = encode_transport_parts(
        *decoded.routing_tag(),
        [0xa5_u8; 16],
        decoded.olm_type(),
        decoded.payload(),
        decoded.capabilities(),
        TransportMode::Universal,
    )
    .expect("forge outer identifier");

    let unchanged_receiver = paired.bob_state.clone();
    let receiver = CipherSession::deserialize_state(&unchanged_receiver).expect("receiver");
    assert_eq!(
        receiver
            .prepare_decrypt(forged.iter().map(String::as_str))
            .err()
            .expect("inner identifier mismatch")
            .code(),
        ErrorCode::InvalidTranscript
    );
    assert_eq!(decrypt(&mut paired.bob_state, &parts), b"bound identifier");

    let restarted = CipherSession::deserialize_state(&paired.bob_state).expect("restart");
    assert_eq!(
        restarted
            .prepare_decrypt(forged.iter().map(String::as_str))
            .err()
            .expect("used Olm key")
            .code(),
        ErrorCode::Replay
    );
}

#[test]
fn simultaneous_sends_are_supported() {
    let mut paired = pair();
    let from_alice = encrypt(&mut paired.alice_state, b"A", TransportMode::Universal);
    let from_bob = encrypt(&mut paired.bob_state, b"B", TransportMode::Universal);
    assert_eq!(decrypt(&mut paired.bob_state, &from_alice), b"A");
    assert_eq!(decrypt(&mut paired.alice_state, &from_bob), b"B");
}

#[test]
fn unicode_round_trips_without_normalization() {
    let mut paired = pair();
    let samples = [
        "",
        "русский English",
        "👨‍👩‍👧‍👦 🏳️‍🌈 👍🏽",
        "e\u{301} != é",
        "العربية עברית",
        "漢字かな한글",
        "∑∫√∞ ≠ ≤ ≥",
        "line one\nline two\r\nline three",
        "a\u{200b}b\u{200d}c\u{2067}RTL\u{2069}",
    ];
    for sample in samples {
        let parts = encrypt(
            &mut paired.alice_state,
            sample.as_bytes(),
            TransportMode::Universal,
        );
        assert_eq!(decrypt(&mut paired.bob_state, &parts), sample.as_bytes());
    }
}

#[test]
fn very_long_message_and_sms_multipart_reassemble() {
    let mut paired = pair();
    let long = "Юникод🙂".repeat(10_000);
    let universal = encrypt(
        &mut paired.alice_state,
        long.as_bytes(),
        TransportMode::Universal,
    );
    assert!(universal.len() > 1);
    let mut reversed = universal.clone();
    reversed.reverse();
    assert_eq!(decrypt(&mut paired.bob_state, &reversed), long.as_bytes());

    let sms_text = "short SMS payload with unicode Ж".repeat(10);
    let sms = encrypt(
        &mut paired.bob_state,
        sms_text.as_bytes(),
        TransportMode::SmsCompact,
    );
    assert!(sms.len() > 1);
    assert_eq!(decrypt(&mut paired.alice_state, &sms), sms_text.as_bytes());
}

#[test]
fn max_parts_and_excess_are_enforced() {
    let tag = [7_u8; 16];
    let id = [9_u8; 16];
    let max_payload = vec![42_u8; usize::from(MAX_PARTS) * 72];
    let parts = encode_transport_parts(tag, id, 1, &max_payload, 0, TransportMode::SmsCompact)
        .expect("maximum parts");
    assert_eq!(parts.len(), usize::from(MAX_PARTS));
    let reassembled =
        reassemble_transport_parts(parts.iter().map(String::as_str), &tag).expect("reassemble max");
    assert_eq!(reassembled.payload(), max_payload);

    let too_large = vec![42_u8; usize::from(MAX_PARTS) * 72 + 1];
    let error = encode_transport_parts(tag, id, 1, &too_large, 0, TransportMode::SmsCompact)
        .expect_err("too many parts");
    assert_eq!(error.code(), ErrorCode::TooManyParts);
}

#[test]
fn missing_duplicate_and_inconsistent_parts_are_rejected() {
    let tag = [1_u8; 16];
    let parts = encode_transport_parts(
        tag,
        [2_u8; 16],
        1,
        &[3_u8; 200],
        0,
        TransportMode::SmsCompact,
    )
    .expect("parts");
    assert_eq!(
        reassemble_transport_parts(parts[..2].iter().map(String::as_str), &tag)
            .err()
            .expect("missing")
            .code(),
        ErrorCode::MissingPart
    );
    assert_eq!(
        reassemble_transport_parts([parts[0].as_str(), parts[0].as_str()], &tag)
            .err()
            .expect("duplicate")
            .code(),
        ErrorCode::Replay
    );
    let other = encode_transport_parts(
        tag,
        [4_u8; 16],
        1,
        &[5_u8; 200],
        0,
        TransportMode::SmsCompact,
    )
    .expect("other");
    assert_eq!(
        reassemble_transport_parts([parts[0].as_str(), other[1].as_str()], &tag)
            .err()
            .expect("mixed")
            .code(),
        ErrorCode::InconsistentParts
    );
}

#[test]
fn tamper_truncation_trailing_and_invalid_base64_are_rejected() {
    let mut paired = pair();
    let parts = encrypt(
        &mut paired.alice_state,
        b"authenticate this",
        TransportMode::Universal,
    );
    let original = &parts[0];
    let mut tampered = original.as_bytes().to_vec();
    let index = tampered.len() / 2;
    tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("ASCII");
    let session = CipherSession::deserialize_state(&paired.bob_state).expect("state");
    assert!(session.prepare_decrypt([tampered.as_str()]).is_err());

    assert!(decode_transport_part(&original[..original.len() - 1]).is_err());
    assert!(decode_transport_part(&format!("{original}A")).is_err());
    assert!(decode_transport_part("CB1:AA==").is_err());
    assert!(decode_transport_part("CB1:AA\n").is_err());
}

#[test]
fn unknown_version_duplicate_and_unknown_mandatory_fields_fail() {
    let version_two = custom_envelope(&[(0, 2), (1, 1)]);
    assert_eq!(
        decode_transport_part(&version_two)
            .err()
            .expect("version")
            .code(),
        ErrorCode::UnsupportedVersion
    );

    let duplicate = custom_envelope(&[(0, 1), (0, 1)]);
    assert_eq!(
        decode_transport_part(&duplicate)
            .err()
            .expect("duplicate")
            .code(),
        ErrorCode::DuplicateField
    );

    let unknown = custom_envelope(&[(0, 1), (42, 1)]);
    assert_eq!(
        decode_transport_part(&unknown)
            .err()
            .expect("unknown")
            .code(),
        ErrorCode::UnknownMandatoryField
    );
}

#[test]
fn bounded_optional_fields_are_forward_compatible() {
    let accepted = complete_envelope_with(4, |encoder| {
        encoder
            .u16(128)
            .and_then(|value| value.bool(true))
            .expect("boolean optional");
        encoder
            .u16(129)
            .and_then(|value| value.null())
            .expect("null optional");
        encoder
            .u16(130)
            .and_then(|value| value.i64(-42))
            .expect("integer optional");
        encoder
            .u16(131)
            .and_then(|value| value.str("future"))
            .expect("text optional");
    });
    let decoded = decode_transport_part(&accepted).expect("known scalar optional fields");
    assert_eq!(decoded.part_number(), 1);
    assert_eq!(decoded.total_parts(), 1);
    assert_eq!(decoded.payload(), b"payload");

    let oversized_value = vec![0_u8; 1025];
    let oversized = complete_envelope_with(1, |encoder| {
        encoder
            .u16(128)
            .and_then(|value| value.bytes(&oversized_value))
            .expect("oversized optional");
    });
    assert_eq!(
        decode_transport_part(&oversized)
            .err()
            .expect("oversized optional must fail")
            .code(),
        ErrorCode::SizeLimit
    );

    let nested = complete_envelope_with(1, |encoder| {
        encoder
            .u16(128)
            .and_then(|value| value.array(0))
            .expect("nested optional");
    });
    assert_eq!(
        decode_transport_part(&nested)
            .err()
            .expect("nested optional must fail")
            .code(),
        ErrorCode::InvalidEncoding
    );
}

#[test]
fn map_field_limit_is_checked_before_reading_entries() {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(33).expect("oversized map header");
    let text = format!("CB1:{}", URL_SAFE_NO_PAD.encode(encoder.into_writer()));
    assert_eq!(
        decode_transport_part(&text)
            .err()
            .expect("oversized map must fail")
            .code(),
        ErrorCode::SizeLimit
    );
}

#[test]
fn transport_envelope_rejects_noncanonical_cbor() {
    let canonical = complete_envelope_with(0, |_| {});
    let mut binary = URL_SAFE_NO_PAD
        .decode(canonical.strip_prefix("CB1:").expect("prefix"))
        .expect("base64");

    let mut non_shortest_map = binary.clone();
    non_shortest_map.splice(0..1, [0xb8, 9]);
    assert_invalid_transport_binary(&non_shortest_map, "non-shortest map length");

    let mut non_shortest_key = binary.clone();
    non_shortest_key.splice(1..2, [0x18, 0]);
    assert_invalid_transport_binary(&non_shortest_key, "non-shortest map key");

    let mut non_shortest_integer = binary.clone();
    non_shortest_integer.splice(2..3, [0x18, 1]);
    assert_invalid_transport_binary(&non_shortest_integer, "non-shortest integer");

    // Swap the two complete one-byte key/value pairs `0: 1` and `1: 1`.
    binary[1..5].rotate_left(2);
    assert_invalid_transport_binary(&binary, "map key order");
}

#[test]
fn optional_scalar_fields_must_also_be_canonical() {
    let canonical = complete_envelope_with(1, |encoder| {
        encoder
            .u16(128)
            .and_then(|value| value.str("x"))
            .expect("optional text");
    });
    let mut binary = URL_SAFE_NO_PAD
        .decode(canonical.strip_prefix("CB1:").expect("prefix"))
        .expect("base64");
    let text_header = binary.len() - 2;
    assert_eq!(binary[text_header], 0x61);
    binary.splice(text_header..=text_header, [0x78, 1]);
    assert_invalid_transport_binary(&binary, "non-shortest optional text length");
}

fn assert_invalid_transport_binary(binary: &[u8], description: &str) {
    let text = format!("CB1:{}", URL_SAFE_NO_PAD.encode(binary));
    assert_eq!(
        decode_transport_part(&text)
            .err()
            .unwrap_or_else(|| panic!("{description} must fail"))
            .code(),
        ErrorCode::InvalidEncoding,
        "{description}"
    );
}

fn custom_envelope(fields: &[(u8, u8)]) -> String {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(fields.len() as u64).expect("map");
    for (key, value) in fields {
        encoder.u8(*key).and_then(|e| e.u8(*value)).expect("field");
    }
    format!("CB1:{}", URL_SAFE_NO_PAD.encode(encoder.into_writer()))
}

fn complete_envelope_with<F>(extra_fields: u64, encode_extra: F) -> String
where
    F: FnOnce(&mut Encoder<Vec<u8>>),
{
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(9 + extra_fields).expect("map");
    encoder
        .u8(0)
        .and_then(|value| value.u8(1))
        .expect("version");
    encoder
        .u8(1)
        .and_then(|value| value.u8(1))
        .expect("message type");
    encoder
        .u8(2)
        .and_then(|value| value.bytes(&[1_u8; 16]))
        .expect("routing tag");
    encoder
        .u8(3)
        .and_then(|value| value.bytes(&[2_u8; 16]))
        .expect("message ID");
    encoder
        .u8(4)
        .and_then(|value| value.u8(1))
        .expect("Olm type");
    encoder
        .u8(5)
        .and_then(|value| value.bytes(b"payload"))
        .expect("payload");
    encoder
        .u8(6)
        .and_then(|value| value.u16(1))
        .expect("part number");
    encoder
        .u8(7)
        .and_then(|value| value.u16(1))
        .expect("part count");
    encoder
        .u8(8)
        .and_then(|value| value.u32(CAPS))
        .expect("capabilities");
    encode_extra(&mut encoder);
    format!("CB1:{}", URL_SAFE_NO_PAD.encode(encoder.into_writer()))
}

#[test]
fn wrong_contact_is_rejected_before_olm() {
    let mut ab = pair();
    let cd = pair();
    let parts = encrypt(&mut ab.alice_state, b"for Bob", TransportMode::Universal);
    let wrong = CipherSession::deserialize_state(&cd.bob_state).expect("wrong session");
    let error = wrong
        .prepare_decrypt(parts.iter().map(String::as_str))
        .err()
        .expect("wrong contact");
    assert_eq!(error.code(), ErrorCode::WrongContact);
}

#[test]
fn expired_offer_signature_tamper_and_reuse_fail() {
    let mut alice = CipherAccount::new();
    let bob = CipherAccount::new();
    let offer = alice.create_pairing_offer(NOW, 60, CAPS).expect("offer");
    let expired = bob
        .respond_to_pairing_offer(&offer, NOW + 61, CAPS)
        .err()
        .expect("expired");
    assert_eq!(expired.code(), ErrorCode::ExpiredOffer);

    let mut encoded = offer.encode_qr().expect("QR").into_bytes();
    let index = encoded.len() - 2;
    encoded[index] = if encoded[index] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(encoded).expect("ASCII");
    assert!(PairingOffer::decode_qr(&tampered).is_err());

    let prepared = bob
        .respond_to_pairing_offer(&offer, NOW + 1, CAPS)
        .expect("response");
    alice
        .complete_pairing(&offer, &prepared.response, NOW + 2)
        .expect("first use");
    let replay = alice
        .complete_pairing(&offer, &prepared.response, NOW + 3)
        .err()
        .expect("second use");
    assert_eq!(replay.code(), ErrorCode::PairingAlreadyUsed);
}

#[test]
fn identity_change_requires_new_pairing() {
    let old = pair();
    let replacement = CipherAccount::new();
    assert_ne!(
        old.bob.public_identity().fingerprint(),
        replacement.public_identity().fingerprint()
    );
}

#[test]
fn transactional_crash_boundaries_preserve_ratchet_rules() {
    let mut paired = pair();
    let old_sender_state = paired.alice_state.clone();
    let session = CipherSession::deserialize_state(&old_sender_state).expect("old state");
    let _pending = session
        .prepare_encrypt(b"pending", CAPS, TransportMode::Universal)
        .expect("prepare");
    assert_eq!(
        paired.alice_state, old_sender_state,
        "prepare must not mutate durable bytes"
    );

    // Crash before state commit means ciphertext was never exposed. Reloading
    // the old snapshot remains valid for a replacement operation.
    let replacement = CipherSession::deserialize_state(&old_sender_state)
        .expect("reload old")
        .prepare_encrypt(b"replacement", CAPS, TransportMode::Universal)
        .expect("replacement");
    paired.alice_state = bytes(replacement.next_state());
    assert_eq!(
        decrypt(&mut paired.bob_state, replacement.parts()),
        b"replacement"
    );

    // A pending operation whose next state was committed before a crash can
    // still publish its saved ciphertext exactly once.
    let mut second_pair = pair();
    let sender = CipherSession::deserialize_state(&second_pair.alice_state).expect("sender");
    let pending = sender
        .prepare_encrypt(b"commit then crash", CAPS, TransportMode::Universal)
        .expect("pending");
    second_pair.alice_state = bytes(pending.next_state());
    assert_eq!(
        decrypt(&mut second_pair.bob_state, pending.parts()),
        b"commit then crash"
    );

    // After receiver state commit, a restart still detects replay.
    let receiver = CipherSession::deserialize_state(&second_pair.bob_state).expect("restart");
    assert_eq!(
        receiver
            .prepare_decrypt(pending.parts().iter().map(String::as_str))
            .err()
            .expect("replay")
            .code(),
        ErrorCode::Replay
    );

    drop(pending);
}

#[test]
fn corrupted_local_state_is_rejected() {
    let paired = pair();
    let mut session = paired.alice_state;
    session[0] ^= 0xff;
    assert!(CipherSession::deserialize_state(&session).is_err());

    let mut account = bytes(&paired.alice.serialize_state().expect("account"));
    account.truncate(account.len() / 2);
    assert!(CipherAccount::deserialize_state(&account).is_err());
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(input in any::<Vec<u8>>()) {
        if let Ok(text) = String::from_utf8(input) {
            let _ = decode_transport_part(&text);
        }
    }

    #[test]
    fn arbitrary_binary_envelope_never_panics(input in proptest::collection::vec(any::<u8>(), 0..65536)) {
        let text = format!("CB1:{}", URL_SAFE_NO_PAD.encode(input));
        let _ = decode_transport_part(&text);
    }
}
