# ADR 0001: Cryptographic library and Android integration

- Status: accepted
- Date: 2026-07-13
- Scope: `crypto-core`, pairing, Olm state storage, JNI

## Context

CipherBoard requires a peer-to-peer protocol for two participants with unique
message keys, forward secrecy, a DH ratchet, support for a bounded number of
out-of-order messages, and replay detection. The application has no server or
network permission, so key discovery, delivery, and contact trust must be built
on reciprocal in-person QR pairing.

Project-local implementations of Double Ratchet, Curve25519, Ed25519, HKDF, a
MAC, or a cipher are out of scope. Cryptographic state must survive process
termination without ratchet rollback and must not be passed to the JVM in
plaintext unless necessary.

## Decision

Use the pure-Rust Olm implementation from `matrix-org/vodozemac`:

| Parameter | Pinned value |
| --- | --- |
| Crate | `vodozemac` |
| Version | `0.10.0` |
| Git tag | `0.10.0` |
| Git commit | `bb39ec65357989f975e0d47f9fb35e0656180151` |
| crates.io SHA-256 checksum | `b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b` |
| Minimum Rust version | `1.85` |
| Rust edition | `2024` |
| License | Apache-2.0 |

The dependency is exact-versioned and `Cargo.lock` is committed:

```toml
[dependencies]
vodozemac = { version = "=0.10.0", default-features = false, features = ["experimental-session-config"] }
```

Only Olm is selected for one-to-one communication. CipherBoard version 1 does
not use Megolm or group sessions.

### Olm configuration

All new CipherBoard sessions use `SessionConfig::version_2()`. Capability
negotiation during QR pairing must include the session configuration version.
A device rejects:

- lack of V2 support;
- a pre-key message using `SessionConfig::version_1()`;
- an unknown mandatory protocol version;
- an attempt to silently downgrade V2 to V1; and
- a session created for a different Curve25519 identity key.

V1 uses an HMAC truncated to 8 bytes. V2 uses a full HMAC, but in vodozemac
0.10.0 it is still gated by the `experimental-session-config` feature. For a
dedicated protocol where both endpoints run the same APK, a full MAC is more
important than compatibility with legacy Matrix/libolm. V2's experimental
status is a known residual risk and requires dedicated interoperability,
mutation, and fuzz tests. Updating vodozemac or changing the session
configuration requires a new ADR and an explicit protocol migration.

### Feature flags and release blockers

The following must not be enabled:

- default feature `libolm-compat`;
- `low-level-api`;
- `insecure-pk-encryption`;
- `js`;
- Megolm API;
- `cfg(fuzzing)` in a production build.

Vodozemac's `cfg(fuzzing)` deliberately disables MAC verification. The release
verification script must inspect Cargo/Rust flags and fail the build if
`--cfg fuzzing` is found. `experimental-session-config` is the only permitted
non-default vodozemac feature.

## Vodozemac API used

The minimal wrapper uses only high-level APIs:

- `Account::new`, `identity_keys`, `sign`;
- `generate_one_time_keys`, `one_time_keys`, `mark_keys_as_published`;
- `Account::create_outbound_session`;
- `Account::create_inbound_session`;
- `Session::encrypt`, `Session::decrypt`;
- `OlmMessage::to_parts`, `OlmMessage::from_parts`;
- `AccountPickle`, `SessionPickle`, and their corresponding `from_pickle`
  methods.

The numeric Olm message type from `OlmMessage::to_parts()` is a mandatory part
of the transport envelope. The input parser first applies CipherBoard's limits,
then passes the bounded byte array to `OlmMessage::from_parts()`.

A successful `create_inbound_session()` simultaneously decrypts the first
pre-key message, consumes the local one-time key, and returns a new session.
The new `AccountPickle` and `SessionPickle`, replay record, and pending display
must therefore be committed in one transaction before plaintext is shown.

Vodozemac bounds retained skipped message keys to five receiving chains, up to
40 keys per chain, and a maximum forward gap of 2000. CipherBoard does not raise
these limits through the low-level API. Replaying an already used Olm message
normally returns `MissingMessageKey`; a persistent bounded replay ledger keyed
by a random CipherBoard message ID is retained as an additional check.

## JNI integration

A small dedicated Rust `cdylib` provides an explicitly defined JNI interface
for `arm64-v8a` and test-only `x86_64`. The official `vodozemac-bindings`
repository is marked unmaintained and is not used. The full
`matrix-sdk-crypto-ffi` is also excluded because it adds a Matrix-specific
state machine, SQLite, and a substantially larger attack surface.

The minimal JNI surface provides operations to:

1. create an identity and return only public keys and sealed account state;
2. create one-time pairing key material;
3. create an outbound session and first pre-key message;
4. create an inbound session from a verified pairing response;
5. encrypt bytes and return the Olm type, ciphertext, and new sealed state;
6. decrypt a bounded Olm message and return plaintext and new sealed state as a
   single result; and
7. return the exact crypto-core version for `BUILD_INFO.txt`.

Long-lived pointers to Rust objects are not passed to Kotlin and do not survive
process death. Each state-mutating operation receives sealed state and returns
its next revision. JNI accepts and returns `ByteArray`, not strings, for
plaintext, keys, and internal state. Plaintext is inevitably copied by the
Android UI and JNI, so absolute zeroization in the JVM is not claimed.

JNI errors are converted to fixed codes without plaintext, ciphertext, QR
payload, contact name, fingerprint, or session state. Secret types must not be
formatted through `Debug`. A panic must not cross the JNI boundary; callers
receive a generic safe error code without the panic message.

Android feasibility is demonstrated by the official Matrix Rust SDK: its
UniFFI crypto bindings depend on vodozemac, build as `cdylib`/`staticlib`, and
document NDK cross-compilation for `aarch64-linux-android`. CipherBoard uses
this as platform evidence but does not reuse the SDK's broad wrapper.

## Serialization and state protection

`AccountPickle` and `SessionPickle` are Serde representations, but vodozemac
does not promise a stable concrete serialization format. Every CipherBoard
record contains its own schema version, vodozemac version, session
configuration, and monotonic local revision fields. An unknown version is not
deserialized as the current version.

The built-in encrypted pickle is not the sole at-rest protection. Its
implementation inherits deterministic AES-CBC IV derivation from the pickle
key and the legacy pickle's 8-byte MAC. The state is therefore additionally
placed in an authenticated secure-storage record with a fresh random nonce and
AAD containing at least the record type, internal contact ID, schema version,
and revision. The top-level key is protected by Android Keystore under the
Vault policy. Nonce reuse is prohibited and covered by tests.

Temporary pickle keys, the DEK, and Rust buffers are wrapped in `Zeroizing` or
explicitly cleared immediately after use. They are not logged or included in
panic/error text. Copies created by Serde, JNI, and the Android UI must have the
smallest practical scope; guaranteed deletion of every copy from RAM is not
claimed.

### Send atomicity

Under a lock for the specific session:

1. load and verify the current revision;
2. decrypt the sealed `SessionPickle`;
3. call `Session::encrypt()`;
4. obtain the new state revision and transport ciphertext;
5. save the new sealed state and pending ciphertext in one transaction;
6. allow `InputConnection.commitText(ciphertext)` only after commit; and
7. mark the pending operation complete after successful insertion.

If the process terminates before the database commit, ciphertext does not leave
the application and the old revision remains valid. If the process terminates
after commit, the pending ciphertext is recovered without calling `encrypt()`
again.

### Receive atomicity

Under the same session lock:

1. verify the envelope, routing tag, message ID, and replay ledger;
2. load the current revision;
3. call `Session::decrypt()` into a temporary buffer;
4. save the new sealed state, replay record, and encrypted pending-display
   record in one transaction;
5. show plaintext only after commit; and
6. delete the pending-display record after the protected viewer closes.

A MAC error, incorrect identity/session tag, replay, or exceeded skipped-key
limit must not alter stored state. Concurrent send/decrypt operations for one
contact are serialized; an optimistic revision check rejects a stale result.

## Audit and known limitations

Least Authority completed the only published vodozemac audit on 2022-03-30.
The initial review covered commit
`7c11a501bc316a0bf92a5fe06fee8582aad24897`; verification covered commit
`57d8d87a747653d6d7b7a53acb9a8d8f8de48285`.

The scope excluded:

- Android/Java, Python, and JavaScript bindings;
- integration with a higher-level application; and
- the cryptographic design of Olm and Megolm themselves.

The final report left the following unresolved:

- Issue I: in-memory keys are not protected against swap/memory reads or
  side-channel attacks;
- Issue J: V1's 64-bit MAC is shorter than recommended; and
- Suggestion 8: retained chain/message-key limits are not configurable.

Version 0.10.0 is substantially newer than the audited commits. Neither version
0.10.0 as a whole, V2, nor CipherBoard's JNI wrapper has received a separate
independent audit. This must be stated explicitly in the threat model and the
user-facing security documentation.

Two low-severity advisories have been published officially:

- GHSA-c3hm-hxwf-g5c6: degraded zeroization in 0.5.0 and 0.5.1, fixed in 0.6.0;
  and
- GHSA-j8cm-g7r6-hfpq / CVE-2024-40640: non-constant-time Base64 before 0.7.0,
  fixed in 0.7.0.

The pinned 0.10.0 is outside those affected ranges. Before every release, the
project still runs `cargo audit`, checks GitHub security advisories and the
SBOM, and manually compares new upstream release notes.

## Licensing

Vodozemac is distributed under Apache-2.0. Apache-2.0 is compatible with GPLv3
but not GPLv2-only. The combined CipherBoard APK is distributed under GPLv3;
the Apache-2.0 text, copyright notices, and notices for all transitive crates
are preserved in their original form and included in third-party notices and
the SBOM.

## Alternatives rejected

- A custom Double Ratchet: unacceptable cryptographic and audit surface.
- `libolm`: a legacy C/C++ implementation officially deprecated in favor of
  vodozemac.
- `matrix-org/vodozemac-bindings`: the official repository is marked
  unmaintained.
- The full `matrix-sdk-crypto-ffi`: solves a broader Matrix problem and violates
  CipherBoard's minimal-JNI-surface principle.
- Megolm: intended for groups and does not provide the required one-to-one
  session model.
- An unofficial fork or floating Git dependency: does not provide
  reproducibility or controlled update review.

## Consequences

Positive:

- cryptographic primitives and Double Ratchet are not implemented by the
  project;
- pure Rust reduces the manual-memory-management error surface compared with
  legacy C/C++;
- an exact version, checksum, and lockfile provide a reproducible baseline;
- V2 removes the known 64-bit message-MAC weakness for the dedicated protocol;
  and
- the minimal JNI layer adds no runtime network code or Google Play Services.

Negative and residual:

- V2 has experimental upstream status;
- the 2022 audit does not cover the current version, bindings, or integration;
- memory protection and zeroization are limited by the Rust allocator, JNI, and
  JVM;
- skipped-key limits can make heavily delayed messages undecryptable; and
- security depends on correct QR transcript verification, Android Keystore,
  atomic storage, and rollback prevention, not only on vodozemac.

## Primary sources

- Official 0.10.0 release and signed tag:
  <https://github.com/matrix-org/vodozemac/releases/tag/0.10.0>
- Exact release commit:
  <https://github.com/matrix-org/vodozemac/commit/bb39ec65357989f975e0d47f9fb35e0656180151>
- Crates.io metadata API:
  <https://crates.io/api/v1/crates/vodozemac/0.10.0>
- Cargo manifest 0.10.0:
  <https://raw.githubusercontent.com/matrix-org/vodozemac/0.10.0/Cargo.toml>
- Official crate and pickling documentation:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/>
- Olm Account API:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Account.html>
- Olm Session API:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Session.html>
- SessionConfig V1/V2:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.SessionConfig.html>
- Olm message transport parts:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/enum.OlmMessage.html>
- Decryption and replay-related errors:
  <https://docs.rs/vodozemac/0.10.0/vodozemac/olm/enum.DecryptionError.html>
- Cipher, pickle MAC, and special `cfg(fuzzing)` implementation:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/cipher/mod.rs.html>
- Serialization and pickle-buffer clearing implementation:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/utilities/mod.rs.html>
- Skipped-message-key limits:
  <https://matrix-org.github.io/vodozemac/src/vodozemac/olm/session/receiver_chain.rs.html>
- Official security policy and advisories:
  <https://github.com/matrix-org/vodozemac/security>
- GHSA-c3hm-hxwf-g5c6:
  <https://github.com/matrix-org/vodozemac/security/advisories/GHSA-c3hm-hxwf-g5c6>
- GHSA-j8cm-g7r6-hfpq:
  <https://github.com/matrix-org/vodozemac/security/advisories/GHSA-j8cm-g7r6-hfpq>
- Least Authority audit report:
  <https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf>
- Unmaintained official bindings:
  <https://github.com/matrix-org/vodozemac-bindings>
- Official Android cross-compilation precedent:
  <https://github.com/matrix-org/matrix-rust-sdk/tree/main/bindings/matrix-sdk-crypto-ffi>
- Vodozemac Apache-2.0 license:
  <https://github.com/matrix-org/vodozemac/blob/0.10.0/LICENSE>
- GPLv3/Apache-2.0 compatibility:
  <https://www.gnu.org/philosophy/license-list.html#apache2>
  and <https://www.apache.org/licenses/GPL-compatibility>
