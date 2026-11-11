//! Compatibility fixtures contain only disposable test identities and messages.
//! They were generated with the unchanged vodozemac 0.10.0 implementation.
use cipherboard_crypto::{CipherAccount, CipherSession, ErrorCode, SecretBytes, TransportMode};

const INITIATOR_ACCOUNT: &[u8] =
    include_bytes!("fixtures/legacy-vodozemac-010/initiator-account.bin");
const RESPONDER_ACCOUNT: &[u8] =
    include_bytes!("fixtures/legacy-vodozemac-010/responder-account.bin");
const INITIATOR_SESSION: &[u8] =
    include_bytes!("fixtures/legacy-vodozemac-010/initiator-session.bin");
const RESPONDER_SESSION: &[u8] =
    include_bytes!("fixtures/legacy-vodozemac-010/responder-session.bin");
const AFTER_PENDING: &[u8] =
    include_bytes!("fixtures/legacy-vodozemac-010/responder-after-pending.bin");

#[test]
fn legacy_accounts_preserve_identity_after_upgrade_and_restart() {
    for (account, session) in [
        (INITIATOR_ACCOUNT, INITIATOR_SESSION),
        (RESPONDER_ACCOUNT, RESPONDER_SESSION),
    ] {
        let restored = CipherAccount::deserialize_state(account).expect("legacy account");
        let session = CipherSession::deserialize_state(session).expect("legacy session");
        assert!(restored.public_identity() == session.local_identity());
        let saved = restored.serialize_state().expect("save upgraded account");
        let restarted = CipherAccount::deserialize_state(saved.expose()).expect("restart account");
        assert!(restored.public_identity() == restarted.public_identity());
    }
}

fn pending_parts() -> Vec<String> {
    serde_json::from_slice(include_bytes!(
        "fixtures/legacy-vodozemac-010/pending-parts.json"
    ))
    .expect("synthetic pending transport")
}

fn assert_replay(state: &[u8], parts: &[String]) {
    let session = CipherSession::deserialize_state(state).expect("restart receiver");
    let error = session
        .prepare_decrypt(parts.iter().map(String::as_str))
        .err()
        .expect("legacy replay rejected");
    assert_eq!(error.code(), ErrorCode::Replay);
}

#[test]
fn legacy_pending_ciphertext_and_committed_replay_survive_upgrade() {
    let parts = pending_parts();
    let session = CipherSession::deserialize_state(RESPONDER_SESSION).expect("legacy receiver");
    let inbound = session
        .prepare_decrypt(parts.iter().map(String::as_str))
        .expect("pre-upgrade pending message");
    assert_eq!(
        inbound.plaintext().expose(),
        b"Synthetic legacy pending message"
    );
    assert_replay(inbound.next_state().expose(), &parts);
    assert_replay(AFTER_PENDING, &parts);
}

fn exchange(sender: &[u8], receiver: &[u8], plaintext: &[u8]) -> (SecretBytes, SecretBytes) {
    let outbound = CipherSession::deserialize_state(sender)
        .expect("load sender")
        .prepare_encrypt(plaintext, 11, TransportMode::Universal)
        .expect("continue upgraded sender");
    let inbound = CipherSession::deserialize_state(receiver)
        .expect("load receiver")
        .prepare_decrypt(outbound.parts().iter().map(String::as_str))
        .expect("continue upgraded receiver");
    assert_eq!(inbound.plaintext().expose(), plaintext);
    (
        SecretBytes::from_owned(outbound.next_state().expose().to_vec()),
        SecretBytes::from_owned(inbound.next_state().expose().to_vec()),
    )
}

#[test]
fn legacy_sessions_continue_both_directions_across_new_state_restarts() {
    let (responder, initiator) = exchange(
        AFTER_PENDING,
        INITIATOR_SESSION,
        b"Synthetic reply after upgrading",
    );
    let (_initiator, responder) = exchange(
        initiator.expose(),
        responder.expose(),
        b"Synthetic second message after restarting",
    );
    assert_replay(responder.expose(), &pending_parts());
}
