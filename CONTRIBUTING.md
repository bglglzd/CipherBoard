# Contributing to CipherBoard

CipherBoard welcomes focused bug fixes, tests, documentation, localization, and
security improvements. It is a security-sensitive Android input method, so
changes that would be routine in another application may alter a plaintext,
identity, storage, or ratchet trust boundary here.

By participating, follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). By
submitting a contribution, you confirm that you have the right to provide it
under the repository's applicable licenses.

## Before You Start

1. Read [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md),
   [`ARCHITECTURE.md`](ARCHITECTURE.md), and
   [`THREAT_MODEL.md`](THREAT_MODEL.md).
2. Search open and closed issues for the same problem.
3. For a substantial feature, protocol change, new dependency, permission, or
   trust-boundary change, open a design issue before implementation.
4. For an undisclosed vulnerability, stop and follow [`SECURITY.md`](SECURITY.md)
   instead of opening a public issue or pull request.

Issues, review descriptions, logs, and test fixtures must use synthetic data.
Never publish real message plaintext, complete ciphertext, contact names, QR
payloads, private keys, session/account state, full fingerprints, Safety
Numbers, signing material, or device identifiers.

## Non-Negotiable Invariants

Contributions must preserve these properties:

- Runtime code has no network capability. Do not add `INTERNET`,
  `ACCESS_NETWORK_STATE`, localhost communication, network clients, Firebase,
  Google Play Services, analytics, advertising, or remote crash reporting.
- Secure Composer plaintext never reaches the host editor, clipboard, Intent
  extras, saved state, logs, notifications, files, learning history, or
  analytics. Only ciphertext may pass through `InputConnection.commitText()`.
- Protected-viewer plaintext is not returned to the source app, copied,
  shared, indexed, backed up, or retained after its display lifetime.
- Identity, Olm account/session state, contacts, replay state, and pending
  display records remain encrypted at rest under the authenticated Vault.
- An outbound ratchet advance and its exact pending ciphertext are committed in
  one transaction before host insertion. An inbound ratchet advance, replay
  marker, and encrypted pending display are committed in one transaction before
  rendering.
- Android Auto Backup and device-transfer extraction remain disabled for all
  application data.
- Pairing remains physical, mutual, signed, expiring, and single-use. Identity
  changes require explicit re-pairing and are never silently accepted.
- Cryptographic primitives and the Double Ratchet are provided by reviewed,
  pinned libraries. Do not introduce custom primitives or protocol shortcuts.
- Release policy rejects unreviewed permissions, exported components, ABIs,
  signing certificates, debug fixtures, test code, and network/telemetry SDKs.

If a proposed feature cannot satisfy an invariant, document the conflict in the
design issue rather than weakening the control in code.

## Development Setup

Use the pinned versions in [`BUILD.md`](BUILD.md). The normal environment uses
JDK 17, Android SDK/Build Tools 36.1.0, NDK 28.0.13004108, Rust/Cargo, and
`cargo-ndk`. Import the repository root in Android Studio or build from a shell.

Build and verify a debug APK on Linux or macOS:

```sh
./scripts/build-debug.sh
```

On Windows PowerShell:

```powershell
.\scripts\build-debug.ps1
```

The script runs the repository source-policy and Kotlin-style checks, Android
lint, all application/library debug unit tests, the APK build, and manifest/APK
policy verification. It writes a developer APK under `dist/`.

Never use or commit production signing material. Release signing is deliberately
separate and is described in [`RELEASE.md`](RELEASE.md).

## Choosing the Right Tests

Run the smallest relevant tests while iterating, then the full debug gate before
requesting review.

Android/Kotlin unit tests:

```sh
./gradlew :app:testDebugUnitTest \
  :crypto-core:testDebugUnitTest \
  :pairing:testDebugUnitTest \
  :secure-storage:testDebugUnitTest
```

Release lint:

```sh
./gradlew :app:lintRelease \
  :crypto-core:lintRelease \
  :pairing:lintRelease \
  :secure-storage:lintRelease
```

Rust checks:

```sh
cargo fmt --all --manifest-path crypto-core/native/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/native/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/native/Cargo.toml

cargo fmt --all --manifest-path crypto-core/jni/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/jni/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/jni/Cargo.toml
```

Android instrumentation requires a running API 36 emulator or device:

```sh
./gradlew :crypto-core:connectedDebugAndroidTest \
  :app:connectedDebugAndroidTest
```

Changes to ratchet transactions, process recovery, IME handoff, pairing, QR,
selected-text parsing, storage, Keystore handling, or protected UI require the
corresponding instrumentation and fault-injection coverage in
[`TEST_PLAN.md`](TEST_PLAN.md). Parser changes require regression/property tests
and an appropriate fuzz run. Do not use real secrets as fixtures or snapshots.

## Change-Specific Requirements

### Cryptography and protocol

- Keep Rust dependency versions exact and lockfiles reviewed.
- Use `vodozemac` APIs rather than reimplementing cryptography.
- Keep the JNI surface minimal, stateless, bounded, panic-contained, and free of
  long-lived native handles.
- Zeroize owned secret buffers where practical and keep errors content-free.
- Update `CRYPTO_PROTOCOL.md`, the crypto ADR, compatibility vectors, negative
  tests, property tests, and fuzz corpora when wire/state behavior changes.
- Treat a protocol version, canonical encoding, transcript, routing tag, replay,
  skipped-key, or message-limit change as a security design change.

### Storage and lifecycle

- Preserve optimistic revisions and single SQLite transactions around ratchet
  transitions.
- Test process death before and after each durable boundary. A retry may reuse
  the exact stored ciphertext, but must never encrypt again from stale state.
- Keep all secret records in credential-encrypted, no-backup storage.
- Do not rely on SharedPreferences or the application sandbox alone for secret
  state.
- Handle StrongBox absence, TEE fallback, Vault lock, screen lock, reboot, and
  Keystore invalidation explicitly.

### IME and user interface

- Test both ordinary HeliBoard input and Secure Composer behavior.
- Verify Russian, English, emoji, symbols, multiline fields, orientation, and
  password-field warnings when input behavior changes.
- Do not store secret text in `String`, ViewModel, `SavedStateHandle`, singleton,
  static field, long-lived coroutine, filename, or test output when a bounded,
  wipeable representation is practical.
- Protected UI must retain `FLAG_SECURE`, background clearing, disabled
  selection/share/autofill/content capture, and no lifecycle-state restoration.
- Add every user-visible string to both `values/` and `values-ru/`. Check long
  Russian text, large fonts, TalkBack labels for non-secret controls, landscape,
  and RTL layout behavior.

### Dependencies, permissions, and exported components

- Discuss every new runtime dependency before adding it. Record its exact
  version, license, provenance, runtime behavior, and vulnerability review.
- Update dependency locks intentionally; never introduce a floating version.
- A new permission or exported component needs a written threat analysis and
  release-policy update. Network, contacts, SMS, overlay, package-query, and
  accessibility-service permissions are outside version 1 scope.
- QR processing must remain fully local and must not depend on Play Services or
  a cloud recognition API.
- Keep `THIRD_PARTY_NOTICES.md`, `LICENSES.md`, SBOM generation, and GPL
  corresponding-source obligations current.

### HeliBoard-derived code

CipherBoard retains a large AOSP/OpenBoard/HeliBoard codebase. Useful entry
points include:

- key/touch input: `PointerTracker`, `LatinIME`, and `InputLogic`;
- host editor communication: `RichInputConnection`;
- suggestions: `DictionaryFacilitatorImpl`, `Suggest`, and the suggestion strip;
- layouts: asset layout files, `KeyboardParser`, and `TextKeyData`;
- settings: `SettingsValues`, `Settings`, and `Default`.

Keep unrelated upstream refactors out of security changes. Preserve existing
copyright headers, mark modifications where required, and document any upstream
cherry-pick in `UPSTREAM.md` or the pull request.

## Pull Request Checklist

A reviewable pull request:

- addresses one coherent problem and links its issue or design discussion;
- explains user-visible behavior and security/privacy impact;
- identifies changed trust boundaries and failure modes;
- contains focused tests, including negative and crash-boundary cases where
  relevant;
- updates English and Russian resources and affected architecture/security docs;
- reports the exact commands run and their results;
- contains no generated APK, keystore, password, local SDK path, secret fixture,
  or unrelated formatting churn; and
- keeps the worktree compatible with the full debug build script.

Use the repository pull request template. Maintainers may request a smaller
change, additional tests, or external specialist review before accepting a
security-sensitive modification.
