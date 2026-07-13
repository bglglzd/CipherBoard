use cipherboard_crypto_jni::{dispatch, WIRE_VERSION};
use minicbor::{Decoder, Encoder};
use proptest::prelude::*;

const NOW: u64 = 1_800_000_000;

fn request<F>(fields: u64, encode: F) -> Vec<u8>
where
    F: FnOnce(&mut Encoder<Vec<u8>>),
{
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(fields).expect("request array");
    encoder.u8(WIRE_VERSION).expect("wire version");
    encode(&mut encoder);
    encoder.into_writer()
}

fn success(operation: i32, request: &[u8]) -> Vec<u8> {
    let response = dispatch(operation, request);
    let mut decoder = Decoder::new(response.expose());
    assert_eq!(decoder.array().expect("outer array"), Some(3));
    assert_eq!(decoder.u8().expect("version"), WIRE_VERSION);
    assert_eq!(decoder.u32().expect("status"), 0);
    let payload = decoder.bytes().expect("payload").to_vec();
    assert_eq!(decoder.position(), response.len());
    payload
}

fn create_account() -> Vec<u8> {
    let payload = success(1, &request(1, |_| {}));
    let mut decoder = Decoder::new(&payload);
    assert_eq!(decoder.array().expect("account array"), Some(4));
    let state = decoder.bytes().expect("account state").to_vec();
    assert_eq!(decoder.bytes().expect("curve").len(), 32);
    assert_eq!(decoder.bytes().expect("ed").len(), 32);
    assert_eq!(decoder.bytes().expect("fingerprint").len(), 32);
    assert_eq!(decoder.position(), payload.len());
    state
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_operation_round_trips_alice_and_bob() {
    let versions = success(0, &request(1, |_| {}));
    let mut decoder = Decoder::new(&versions);
    assert_eq!(decoder.array().expect("versions"), Some(2));
    assert_eq!(decoder.u8().expect("protocol"), 1);
    assert_eq!(decoder.u8().expect("Olm"), 2);

    let alice_account = create_account();
    let bob_account = create_account();

    let offer_payload = success(
        2,
        &request(5, |encoder| {
            encoder.bytes(&alice_account).expect("account");
            encoder.u64(NOW).expect("now");
            encoder.u64(600).expect("TTL");
            encoder.u32(7).expect("capabilities");
        }),
    );
    let mut decoder = Decoder::new(&offer_payload);
    assert_eq!(decoder.array().expect("offer result"), Some(2));
    let alice_account = decoder.bytes().expect("updated account").to_vec();
    let offer = decoder.bytes().expect("offer").to_vec();
    assert!(offer.starts_with(b"CBO1:"));

    let offer_metadata = success(
        8,
        &request(3, |encoder| {
            encoder.bytes(&offer).expect("offer");
            encoder.u64(NOW + 1).expect("now");
        }),
    );
    let mut decoder = Decoder::new(&offer_metadata);
    assert_eq!(decoder.array().expect("pairing metadata"), Some(10));
    assert_eq!(decoder.u8().expect("offer type"), 1);
    let pairing_id = decoder.bytes().expect("pairing ID").to_vec();
    assert_eq!(pairing_id.len(), 16);
    assert_eq!(decoder.bytes().expect("remote curve").len(), 32);
    assert_eq!(decoder.bytes().expect("remote ed").len(), 32);
    let offer_fingerprint = decoder.bytes().expect("fingerprint").to_vec();
    assert_eq!(offer_fingerprint.len(), 32);
    assert_eq!(decoder.bytes().expect("nonce").len(), 32);
    assert_eq!(decoder.u32().expect("capabilities"), 7);
    assert_eq!(decoder.u64().expect("expiry"), NOW + 600);
    assert_eq!(decoder.u8().expect("expired"), 0);
    let offer_hash = decoder.bytes().expect("offer hash").to_vec();
    assert_eq!(offer_hash.len(), 32);
    assert_eq!(decoder.position(), offer_metadata.len());

    let expired_metadata = success(
        8,
        &request(3, |encoder| {
            encoder.bytes(&offer).expect("offer");
            encoder.u64(NOW + 601).expect("now");
        }),
    );
    let mut decoder = Decoder::new(&expired_metadata);
    assert_eq!(decoder.array().expect("expired metadata"), Some(10));
    decoder.u8().expect("type");
    decoder.bytes().expect("pairing ID");
    decoder.bytes().expect("curve");
    decoder.bytes().expect("ed");
    decoder.bytes().expect("fingerprint");
    decoder.bytes().expect("nonce");
    decoder.u32().expect("capabilities");
    decoder.u64().expect("expiry");
    assert_eq!(decoder.u8().expect("expired"), 1);

    let response_payload = success(
        3,
        &request(5, |encoder| {
            encoder.bytes(&bob_account).expect("account");
            encoder.bytes(&offer).expect("offer");
            encoder.u64(NOW + 1).expect("now");
            encoder.u32(7).expect("capabilities");
        }),
    );
    let mut decoder = Decoder::new(&response_payload);
    assert_eq!(decoder.array().expect("response result"), Some(9));
    let mut bob_session = decoder.bytes().expect("session").to_vec();
    let response = decoder.bytes().expect("response").to_vec();
    assert!(response.starts_with(b"CBR1:"));
    let bob_safety = decoder.bytes().expect("safety hash").to_vec();
    assert_eq!(decoder.bytes().expect("decimal").len(), 87);
    assert!(!decoder.bytes().expect("words").is_empty());
    assert_eq!(decoder.bytes().expect("remote curve").len(), 32);
    assert_eq!(decoder.bytes().expect("remote ed").len(), 32);
    let bob_routing_tag = decoder.bytes().expect("routing tag").to_vec();
    assert_eq!(bob_routing_tag.len(), 16);
    assert_eq!(
        decoder.bytes().expect("remote fingerprint"),
        offer_fingerprint
    );

    let response_metadata = success(
        8,
        &request(3, |encoder| {
            encoder.bytes(&response).expect("response");
            encoder.u64(NOW + 2).expect("now");
        }),
    );
    let mut decoder = Decoder::new(&response_metadata);
    assert_eq!(decoder.array().expect("response metadata"), Some(10));
    assert_eq!(decoder.u8().expect("response type"), 2);
    assert_eq!(decoder.bytes().expect("pairing ID"), pairing_id);
    assert_eq!(decoder.bytes().expect("remote curve").len(), 32);
    assert_eq!(decoder.bytes().expect("remote ed").len(), 32);
    let response_fingerprint = decoder.bytes().expect("fingerprint").to_vec();
    assert_eq!(response_fingerprint.len(), 32);
    assert_eq!(decoder.bytes().expect("nonce").len(), 32);
    assert_eq!(decoder.u32().expect("capabilities"), 7);
    assert_eq!(decoder.u64().expect("no expiry"), 0);
    assert_eq!(decoder.u8().expect("not expired"), 0);
    assert_eq!(decoder.bytes().expect("offer hash"), offer_hash);

    let complete_payload = success(
        4,
        &request(5, |encoder| {
            encoder.bytes(&alice_account).expect("account");
            encoder.bytes(&offer).expect("offer");
            encoder.bytes(&response).expect("response");
            encoder.u64(NOW + 2).expect("now");
        }),
    );
    let mut decoder = Decoder::new(&complete_payload);
    assert_eq!(decoder.array().expect("completion"), Some(10));
    let _alice_account = decoder.bytes().expect("updated account");
    let mut alice_session = decoder.bytes().expect("session").to_vec();
    assert!(decoder.bytes().expect("empty response").is_empty());
    assert_eq!(decoder.bytes().expect("safety"), bob_safety);
    let _decimal = decoder.bytes().expect("decimal");
    let _words = decoder.bytes().expect("words");
    assert_eq!(decoder.bytes().expect("remote curve").len(), 32);
    assert_eq!(decoder.bytes().expect("remote ed").len(), 32);
    assert_eq!(decoder.bytes().expect("routing tag"), bob_routing_tag);
    assert_eq!(
        decoder.bytes().expect("remote fingerprint"),
        response_fingerprint
    );

    let plaintext = "JNI: Привет 👋".as_bytes();
    let encrypted_payload = success(
        5,
        &request(5, |encoder| {
            encoder.bytes(&alice_session).expect("session");
            encoder.bytes(plaintext).expect("plaintext");
            encoder.u32(7).expect("capabilities");
            encoder.u8(0).expect("mode");
        }),
    );
    let mut decoder = Decoder::new(&encrypted_payload);
    assert_eq!(decoder.array().expect("encrypt result"), Some(3));
    alice_session = decoder.bytes().expect("next session").to_vec();
    let message_id = decoder.bytes().expect("message ID").to_vec();
    let count = decoder.array().expect("parts").expect("definite parts");
    let mut parts = Vec::new();
    for _ in 0..count {
        parts.push(decoder.bytes().expect("part").to_vec());
    }

    let metadata = success(
        7,
        &request(2, |encoder| {
            encoder.bytes(&parts[0]).expect("part");
        }),
    );
    let mut decoder = Decoder::new(&metadata);
    assert_eq!(decoder.array().expect("metadata"), Some(7));
    assert_eq!(decoder.bytes().expect("routing").len(), 16);
    assert_eq!(decoder.bytes().expect("message ID"), message_id);
    assert_eq!(decoder.u16().expect("part"), 1);
    assert_eq!(
        decoder.u16().expect("total"),
        u16::try_from(count).expect("bounded part count")
    );
    assert_eq!(decoder.u32().expect("capabilities"), 7);
    let _olm_type = decoder.u8().expect("Olm type");
    assert!(decoder.u32().expect("payload bytes") > 0);

    let decrypted_payload = success(
        6,
        &request(3, |encoder| {
            encoder.bytes(&bob_session).expect("session");
            encoder.array(count).expect("parts");
            for part in &parts {
                encoder.bytes(part).expect("part");
            }
        }),
    );
    let mut decoder = Decoder::new(&decrypted_payload);
    assert_eq!(decoder.array().expect("decrypt result"), Some(3));
    bob_session = decoder.bytes().expect("next session").to_vec();
    assert_eq!(decoder.bytes().expect("message ID"), message_id);
    assert_eq!(decoder.bytes().expect("plaintext"), plaintext);

    assert!(!alice_session.is_empty());
    assert!(!bob_session.is_empty());
}

#[test]
fn malformed_and_unknown_requests_return_stable_errors() {
    for (operation, input) in [(999, vec![0x81, 0x01]), (1, vec![]), (0, vec![0x81, 0x02])] {
        let response = dispatch(operation, &input);
        let mut decoder = Decoder::new(response.expose());
        assert_eq!(decoder.array().expect("outer"), Some(3));
        assert_eq!(decoder.u8().expect("version"), WIRE_VERSION);
        assert_ne!(decoder.u32().expect("error"), 0);
        assert!(decoder.bytes().expect("empty").is_empty());
    }
}

proptest! {
    #[test]
    fn arbitrary_requests_never_panic(operation in any::<i32>(), input in proptest::collection::vec(any::<u8>(), 0..65536)) {
        let response = dispatch(operation, &input);
        prop_assert!(!response.is_empty());
    }
}
