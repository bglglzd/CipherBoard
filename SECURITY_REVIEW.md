# CipherBoard Security Review Status

Review date: 2026-07-13. This is an internal engineering review, not an
independent security audit and not a production release approval.

## Reviewed Evidence

The following evidence was observed for the committed crypto/JNI baseline:

- `vodozemac 0.10.0` is exact-versioned with default features disabled and Olm
  `SessionConfig::version_2()` enforced.
- Cargo dependency graphs are fixed by two lockfiles; `cargo audit` reported no
  known advisories at review time.
- Native crypto tests: 20 passing, including 1000 messages, bounded
  out-of-order delivery, replay after restart, tamper/truncation, Unicode,
  multipart limits, corrupt state and transactional crash boundaries.
- JNI host tests: three passing suites covering all opcodes, Alice/Bob pairing,
  encrypt/decrypt, malformed input and property-generated arbitrary requests.
- Android JNI instrumentation: one full Alice/Bob identity, QR transcript,
  encrypt/decrypt and zeroization smoke test passed on an API 36 x86_64 AOSP
  emulator.
- Strict Rust formatting and Clippy passed; no raw native state handles cross
  JNI. JNI exposes one `nativeInvoke(Int, ByteArray): ByteArray` operation.
- The source manifest declares backup exclusion and cleartext disabled. The
  repository contains no WebView or dynamic-code-loader use found by source
  search.

This evidence proves only the tested module behavior at that point in time. It
does not prove behavior of a future final APK.

## Security Controls Implemented

| Area | Current control |
| --- | --- |
| Crypto | vodozemac Olm v2; signed QR transcript; exact Cargo versions |
| Transport | strict bounded CBOR/base64url parser; multipart consistency; inner message-ID binding |
| Replay | bounded persistent message IDs plus Olm used-key rejection |
| State transitions | consuming prepare APIs return `next_state` before ciphertext/plaintext exposure |
| JNI | bounded versioned CBOR, stable numeric errors, no native pointer handles, temporary buffer zeroization |
| Storage module | Keystore wrapping, StrongBox attempt/TEE fallback, authenticated records and lock policy code exists |
| Pairing module | offline ZXing decoding and CameraX scanner module; camera is requested by the UI layer when used |
| Manifest source | backup disabled; cleartext disabled; forbidden permission test code exists |
| Release verifier | independent aapt/apkanalyzer/apksigner/zipalign/XML/DEX checks |

## Release Blockers

### Critical

1. **End-to-end product workflow is incomplete.** The application does not yet
   expose the required Secure Composer, protected plaintext viewer,
   `ACTION_PROCESS_TEXT` decrypt activity, selected-text decrypt flow, secure
   reply, or complete contacts UI. Module tests cannot satisfy product
   acceptance criteria.
2. **Atomic storage integration is not demonstrated end to end.** The crypto
   API returns transactional next state and the storage module has pending
   records, but the application has not demonstrated atomic commit before
   `InputConnection.commitText()` or before plaintext display across forced
   process crashes.
3. **Plaintext leakage controls are not verified in the final UI.** There is no
   final evidence for `FLAG_SECURE`, recent-task redaction, background clearing,
   accessibility/Assistant behavior, clipboard exclusion, saved-state
   exclusion, no-learning mode, or logcat scans during the real workflow.

### High

4. **No production-signed APK has been produced or independently verified.** A
   release certificate fingerprint and final permission list do not exist yet.
5. **Gradle transitives are not locked.** Direct versions are declared, but no
   Gradle lockfiles are checked in. Builds are not yet reproducible.
6. **Generated dependency evidence still requires release review.** The release
   scripts generate CycloneDX `SBOM.json` and `BUILD_INFO.txt`, but Gradle
   transitives remain unlocked and any SBOM component marked
   `cipherboard:licenseReview=required` must be resolved before publication.
7. **Hardware-backed Keystore behavior is not proven on physical devices.**
   StrongBox success, TEE fallback, key invalidation after lock-screen changes,
   reboot behavior, biometric/device-credential flows and rollback resistance
   need instrumentation on relevant GrapheneOS devices.
8. **Pairing lifecycle integration remains incomplete.** Expiry and OTK
   consumption exist in crypto; cancellation, persisted pending offers,
   duplicate QR UX, verified-state transitions and re-pairing/key-change alarms
   require application-level tests.

### Medium

9. **Parser fuzzing is property-based, not a sustained native fuzz campaign.**
   Add coverage-guided fuzzing with a retained corpus for transport and JNI
   request codecs.
10. **Exported-component policy is structural.** The verifier rejects unknown
    exported shapes, but every exported intent handler still needs manual
    validation review and malicious-intent instrumentation.
11. **JNI uses `panic=abort` in release.** Expected failures are returned as
    fixed codes, but an unexpected Rust panic terminates the process. Continue
    removing panic paths and fuzz the exact release configuration.
12. **Best-effort zeroization has platform limits.** Rust and owned Kotlin
    buffers are cleared, but JVM strings, UI widgets, allocator copies and
    operating-system memory may retain data. No guarantee of complete RAM
    erasure is made.
13. **Signing automation temporarily materializes passwords.** They are stored
    only in restricted temporary files and never placed in command arguments,
    but shell/JVM memory cannot be guaranteed to zeroize. Prefer a dedicated
    offline signing environment or hardware-backed signing process for high
    assurance.

## APK Policy Review

`scripts/verify-apk` fails on:

- Internet/network-state, contacts, SMS, overlay, broad package query and
  accessibility-service permissions;
- backup/cleartext, release debuggable/testOnly, unknown exported components,
  exported providers and HTTP(S) deep links;
- Firebase, GMS, advertising, analytics, crash SDK, WebView and dynamic loader
  byte markers;
- invalid signing, missing v2 signing, debug release certificate, or bad ZIP
  alignment.

This scanner does not establish that a component validates every semantic
input, does not prove absence of native memory-safety defects, and cannot find
all obfuscated malicious behavior. Treat it as a blocker test plus manual
review, not an audit.

## Dependency and License Review

- HeliBoard upstream is pinned by full commit but its selected upstream commit
  is unsigned; provenance is exact but not cryptographically attested.
- Rust Cargo metadata contains license fields for every locked package.
- vodozemac is Apache-2.0, compatible for aggregation with GPLv3 when Apache
  notices and GPL corresponding-source duties are met.
- Android direct versions and their license metadata are recorded in
  `LICENSES.md`; absence of Gradle locking remains open.
- No Firebase, Google Play Services, analytics, crash-reporting or ad dependency
  is declared in the reviewed build files.

## Required Work Before High-risk Use

1. Finish the application workflow and all critical controls above.
2. Enable Gradle dependency locking, generate/review SBOM and reproducible build
   information, and rebuild from a clean environment.
3. Execute forced-crash atomicity tests at each persistent transition on real
   Android storage.
4. Perform GrapheneOS testing without Google Play on physical StrongBox and TEE
   devices.
5. Run leakage tests against logcat, clipboard, saved state, recents,
   screenshots, Assistant and Accessibility.
6. Obtain independent applied-cryptography and Android security review.

CipherBoard uses reviewed cryptographic primitives and has automated module
tests, but the whole product must not be considered independently audited until
external specialists have reviewed the integrated application and final build.
