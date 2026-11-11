# ADR 0003: Update the pinned crypto library without replacing stored identities

- Status: accepted; supersedes ADR 0001's dependency pin, not its Olm v2 decision
- Date: 2026-11-11
- Scope: native/JNI Cargo graphs, persisted account/session compatibility

## Reason

The former vodozemac 0.10.0 pin is affected by the published
[RUSTSEC-2026-0451 advisory](https://rustsec.org/advisories/RUSTSEC-2026-0451.html).
Use the patched release rather than suppressing the audit. Upstream 0.11.2 also
fixes malformed Ed25519 base64 input handling and enables/extends zeroization
in its RustCrypto dependency graph. This does not promise complete memory
erasure through the allocator, JNI or JVM.

## Decision and provenance

| Input | Value |
| --- | --- |
| vodozemac version/tag | `0.11.2` |
| Tag commit | `fb4a9980a1038c646824ea7e64567eec28bf582e` |
| crates.io SHA-256 | `cafdb6875115a436251b280d741286a9cec7fc4daab0588ea26481dd8e2bab2f` |
| Required Rust | at least `1.89`; this project retains `1.94.0` |
| License | Apache-2.0 |
| Features | defaults disabled; `experimental-session-config` enabled |

Retain `SessionConfig::version_2()`, the full MAC, the existing CB1/CBW1 wire
formats, domain labels, routing, pairing validation, replay ledger and Android
transaction boundaries. No custom primitive or new runtime permission is added.
The new upstream HPKE APIs are not used. Serde/serde_json/zeroize exact pins are
advanced to the minimum versions required by this release; the complete new
transitive graphs are committed in both native and JNI lockfiles. The standalone
transport-parser fuzz graph does not depend on vodozemac.

## Stored-state policy and verification

Keep the existing CBA1/CBS1 schema and restore existing identities and ratchets.
The six provenance-bound, pre-upgrade synthetic fixtures under
`crypto-core/native/tests/fixtures/legacy-vodozemac-010` were produced by the old
implementation, not reconstructed with the new dependency. Tests require:

- account identity continuity after restore and new serialization/restart;
- decryption of a pre-upgrade pending ciphertext;
- replay rejection from both the old committed state and the upgraded state;
- subsequent bidirectional exchanges through serialized upgraded states.

Malformed or unsupported stored state still fails closed. The application must
not silently generate a replacement identity or clear a user's Vault. These
checks are library-level evidence; device-to-device camera exchange and physical
Keystore acceptance remain separate platform checks. This maintenance change
does not publish an APK or authorize reinstalling/clearing existing app data.

The 2022 external audit did not cover this version or CipherBoard's integration.
Updating a dependency does not make the whole product independently audited.

## Sources

- [Upstream release and changes](https://github.com/matrix-org/vodozemac/releases/tag/0.11.2)
- [Pinned Cargo manifest](https://github.com/matrix-org/vodozemac/blob/fb4a9980a1038c646824ea7e64567eec28bf582e/Cargo.toml)
- [Registry checksum and metadata](https://crates.io/api/v1/crates/vodozemac/0.11.2)
