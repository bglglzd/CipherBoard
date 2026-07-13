# CipherBoard Security Checklist

**Snapshot date:** 2026-07-13  
**Branch:** `feature/secure-messaging-keyboard`  
**Upstream baseline:** HeliBoard `v4.0`, commit
`bd48798b99cccc99704eebf2a9259c02dbd684d5`

This is a traceable implementation and release checklist. It is not a security
certificate. Update an item's state only with evidence tied to the current
commit and, where applicable, the exact APK.

## State Definitions

- **Pending**: not implemented, not inspected, incomplete, or evidence is not
  yet available for the current commit/artifact.
- **Implemented**: code or documentation exists, but the required independent
  test/review or final-artifact evidence is incomplete.
- **Verified**: the stated verification was performed successfully against the
  identified commit/artifact and its evidence is recorded.

`Verified` does not mean independently audited unless the evidence explicitly
names an external review and its scope. A later relevant code, dependency,
manifest, build, signing, or configuration change returns affected items to
`Implemented` or `Pending`.

## 1. Provenance, Governance, and Documentation

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| GOV-01 | Source is based on official HeliBoard stable tag `v4.0` at the recorded commit | 5 | Verified | `git tag --points-at HEAD` and `git rev-parse HEAD` were checked before product changes |
| GOV-02 | Product branch is `feature/secure-messaging-keyboard` | 4 | Verified | `git status --short --branch`, 2026-07-13 |
| GOV-03 | Upstream tag/commit and modification relationship are recorded | 5 | Implemented | `UPSTREAM.md`; review before release |
| GOV-04 | GPLv3 license, source obligations, and upstream notices are preserved | 5 | Pending | License/notices review and release source archive |
| GOV-05 | Third-party versions, licenses, and notices are complete | 5, 30 | Pending | `LICENSES.md`, `THIRD_PARTY_NOTICES.md`, generated notice artifact |
| GOV-06 | Threat model accurately states scope and residual risk | 3 | Implemented | `THREAT_MODEL.md`; independent security review pending |
| GOV-07 | Architecture, crypto protocol, build, release, and test documents match code | 6, 30 | Pending | Document-to-code review at release candidate |
| GOV-08 | UI/README contain no absolute-security or independent-audit claims | 3, 33 | Pending | Resource and documentation string scan |
| GOV-09 | No passwords, private keys, signing files, or credentials are tracked | 4, 29 | Pending | Secret scan plus Git history review |

## 2. Runtime Network and Dependency Boundary

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| NET-01 | Final merged manifest has no `android.permission.INTERNET` | 2, 19, 28 | Pending | `aapt dump permissions` and `apkanalyzer` on signed release; release blocker |
| NET-02 | No `ACCESS_NETWORK_STATE` or other network permission | 2, 19 | Pending | Merged-manifest and APK inspection |
| NET-03 | Runtime performs no network or localhost request | 2 | Pending | Dependency/code scan and device traffic test with denied Network permission |
| NET-04 | No Firebase, FCM, Play Services, analytics, crash-reporting, advertising, or remote-config SDK | 2, 20, 28 | Pending | Dependency graph, SBOM, APK class/string scan |
| NET-05 | No WebView, dynamic code loading, downloaded model/dictionary/configuration, or proprietary cloud QR API | 2, 19, 27 | Pending | Source/dependency scan and runtime test |
| NET-06 | App works on GrapheneOS without Sandboxed Google Play | 20, 31 | Pending | Physical-device acceptance evidence |
| NET-07 | GrapheneOS Network denial is documented as defense in depth | 20 | Pending | Installation/security documentation review |

## 3. Cryptographic Library and FFI

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| CRY-01 | Crypto ADR evaluates official `vodozemac`, security policy, audits, support, and Apache-2.0/GPLv3 compatibility | 7.2 | Pending | `docs/adr/0001-crypto-library.md` review |
| CRY-02 | Exact crypto library version/commit is pinned and dependency-locked | 7.2, 27 | Pending | Lockfiles, SBOM, build info |
| CRY-03 | No custom Curve25519, Ed25519, AEAD, HKDF, ratchet, RNG, hash, signature, or PGP-like scheme | 7.1 | Pending | Crypto-focused source review |
| CRY-04 | v1 uses one-to-one Olm/Double Ratchet, not Megolm/group sessions | 7.2 | Pending | Protocol tests and dependency/API review |
| CRY-05 | FFI API is minimal, length checked, typed, and does not stringify keys/state | 7.2, 24 | Pending | Rust/Kotlin boundary review and malformed-input tests |
| CRY-06 | Secret Rust buffers use `zeroize` where ownership permits and do not leak through `Debug`/panic | 7.2, 24 | Pending | Rust review, clippy, panic/error tests |
| CRY-07 | Sender authentication, integrity, forward secrecy, DH and symmetric ratchets are exercised end to end | 7.3, 25 | Pending | Alice/Bob protocol test report |
| CRY-08 | Skipped-key storage is bounded and used keys are not retained | 7.3 | Pending | Limit tests and state inspection using test fixtures only |
| CRY-09 | Crypto/dependency security advisories are reviewed for the pinned versions | 7.2, 27 | Pending | `cargo audit`, dependency review, recorded exceptions |

## 4. Identity and Pairing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| ID-01 | First run creates a local identity without registration or network identifier | 8 | Pending | Unit/instrumentation test |
| ID-02 | Local owner/contact names are not cryptographic identity and are not shared without confirmation | 8, 9 | Pending | QR fixture inspection and UI test |
| ID-03 | Clearing data/reinstalling creates a new identity and requires re-pairing | 8, 10 | Pending | Lifecycle instrumentation test |
| ID-04 | Identity replacement produces blocking `Key changed`/`Pairing required`, never silent acceptance | 8, 10 | Pending | Key-change integration test |
| PAIR-01 | Pairing offer has random ID/nonce, expiry, one-time key material, protocol version, and bounded capabilities | 9 | Pending | Canonical pairing fixture and parser tests |
| PAIR-02 | Pairing payload excludes phone/email/device/account/location/system-contact identifiers | 9 | Pending | Schema review and decoded QR fixture |
| PAIR-03 | Pairing offer is single-use; replay, expiry, duplicate import, and deletion are enforced | 9, 25 | Pending | Replay/expiry/crash tests |
| PAIR-04 | Response cryptographically binds both identities and complete transcript | 9 | Pending | Alice/Bob transcript test |
| PAIR-05 | Both devices derive identical numeric and emoji/word codes from one transcript hash | 9, 25 | Pending | Cross-device deterministic vectors |
| PAIR-06 | Contact becomes `Verified` only after explicit Safety Number comparison/confirmation | 9 | Pending | UI/state-machine test |
| PAIR-07 | QR scanning is offline, parser-bounded, and requests camera only after user action | 19 | Pending | Permission/UI test and dependency review |
| PAIR-08 | Remote pairing through a messenger is absent in v1 | 9 | Pending | Exported-intent and UI review |

## 5. Contacts and Session Lifecycle

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| CON-01 | Contacts store only required local fields and encrypted session/replay state | 10, 16 | Pending | Schema/storage review |
| CON-02 | Add, rename, fingerprint/Safety Number view, reverify, delete, reset, and re-pair flows work | 10 | Pending | UI/instrumentation tests |
| CON-03 | Deletion removes local session material as reliably as Android permits and explains flash-storage limits | 10, 16 | Pending | Deletion tests and documentation review |
| CON-04 | Public fingerprint export contains no private/contact/system metadata | 10 | Pending | Export fixture test |
| CON-05 | Damaged sessions fail closed with `Session error` and require explicit recovery | 7.3, 10 | Pending | Corrupt-state tests |

## 6. Envelope, Unicode, and Multipart Parsing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| ENV-01 | Outer format is versioned `CB1:` with Base64url without padding and deterministic binary encoding | 12 | Pending | Golden vectors and cross-run determinism tests |
| ENV-02 | Envelope exposes only required opaque routing/reassembly metadata; sensitive metadata is encrypted | 12 | Pending | Schema and fixture review |
| ENV-03 | Parser rejects invalid Base64, duplicate/unknown mandatory fields, trailing bytes, invalid versions, and inconsistent IDs | 12, 25 | Pending | Unit/property/fuzz corpus |
| ENV-04 | Parser enforces input, field, nesting, allocation, part-count, and total-size limits | 12, 13 | Pending | Boundary and memory tests |
| ENV-05 | Multipart assembly is order independent, detects gaps/duplicates, and decrypts only when complete | 13 | Pending | Permutation/missing-part tests |
| ENV-06 | Universal and SMS compact modes use transport-safe ASCII and report size/part estimates | 13 | Pending | GSM/SMS fixture and UI tests |
| ENV-07 | Plaintext is not compressed by default | 13 | Pending | Protocol/config review |
| ENV-08 | UTF-8 round trip is byte-exact without normalization for required Unicode classes | 12, 25 | Pending | Unicode vector suite |
| ENV-09 | Arbitrary parser input cannot panic/crash or allocate without bound | 25 | Pending | Property tests and fuzz report |

## 7. Ratchet Atomicity and Replay

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| RAT-01 | Send transaction atomically commits advanced state plus exact pending ciphertext before host commit | 17 | Pending | Transaction code review and crash injection |
| RAT-02 | Recovery reuses pending ciphertext and never encrypts again from stale state | 17 | Pending | Process-kill/restart test |
| RAT-03 | Receive transaction commits advanced state plus encrypted pending display before showing plaintext | 17 | Pending | Transaction code review and crash injection |
| RAT-04 | Pending display is removed on close with no retained message key/plaintext history | 17, 18 | Pending | Storage/lifecycle test |
| RAT-05 | Replay is rejected across process/device restart | 7.3, 17, 25 | Pending | Persistent replay test |
| RAT-06 | Out-of-order and skipped messages work within fixed bounds | 7.3, 25 | Pending | Shuffled/omitted 1000-message suite |
| RAT-07 | Concurrent send attempts serialize safely per session | 25 | Pending | Concurrency stress test |
| RAT-08 | Crash points before/after save and before host transfer cannot reuse ratchet state | 17, 25 | Pending | Fault-injection matrix |
| RAT-09 | Backup/restore and cloning of ratchet state are disabled; privileged same-device rollback remains documented residual risk | 16, 17 | Pending | Rules/APK review, backup test, threat-model review |

## 8. Keystore, Vault, and Encrypted Storage

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| STO-01 | Non-exportable wrapping key is generated in Android Keystore | 16 | Pending | Instrumented KeyInfo evidence without key material |
| STO-02 | StrongBox is attempted first; TEE fallback is nonfatal and actual security level is shown | 16, 25 | Pending | StrongBox device and no-StrongBox emulator/device tests |
| STO-03 | Wrapping key requires `BIOMETRIC_STRONG` or device credential | 16 | Pending | Authentication policy test |
| STO-04 | Identity, ratchet, replay, pairing, contact, and pending records are authenticated-encrypted | 16 | Pending | Storage/schema and stolen-database tests |
| STO-05 | No master/private key is stored in preferences, assets, source, BuildConfig, logs, or exported files | 16, 23 | Pending | Source/APK/storage scans |
| STO-06 | Vault policies include immediate/30 s/1 min/5 min with 1 min default | 16 | Pending | Unit/UI tests |
| STO-07 | Vault locks on boot, screen lock, manual action, timeout, and key invalidation | 16 | Pending | Lifecycle instrumentation tests |
| STO-08 | Keystore invalidation fails closed and requires explicit recovery/re-pairing | 16, 25 | Pending | Invalidation test |
| STO-09 | `allowBackup=false` and data extraction rules exclude all CipherBoard data | 16, 27 | Pending | Merged manifest, APK, `bmgr`/transfer test |
| STO-10 | v1 has no identity, ratchet, secret, message-key, or plaintext-history export/restore | 16, 18 | Pending | UI/intent/storage review |
| STO-11 | Database corruption is detected without plaintext fallback or silent identity reset | 25 | Pending | Corruption test matrix |

## 9. Secure Composer and Keyboard

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| IME-01 | Ordinary HeliBoard English/Russian/emoji/symbol/Unicode input remains functional | 5, 26, 31 | Pending | Regression/instrumentation suite |
| IME-02 | Shield action opens an explicit CipherBoard-owned secure composer | 11 | Pending | IME UI test |
| IME-03 | Plaintext never reaches host `InputConnection`, composing region, or key events | 11, 31 | Pending | Host `EditText` spy instrumentation test |
| IME-04 | Only ciphertext is committed with `commitText()` after explicit encryption | 11 | Pending | InputConnection capture test |
| IME-05 | Plaintext composer clears after successful transaction/commit attempt and on close/lock/background | 11, 15 | Pending | Lifecycle and memory-reference tests |
| IME-06 | Secure mode disables personalized learning, user dictionary, input history, drafts, and clipboard history | 11, 23 | Pending | IME flags/config/storage tests |
| IME-07 | Plaintext is absent from saved state, long-lived ViewModels, intents, preferences, files, cache, and database | 11, 23 | Pending | Process-death/storage scan tests |
| IME-08 | Secure composer shows contact verification, vault state, size estimates, clear/close/encrypt controls | 11 | Pending | UI/accessibility test |
| IME-09 | Password fields show an explicit warning; no automatic encryption/commit occurs | 26 | Pending | Password-field instrumentation test |
| IME-10 | Layout handles large fonts, landscape, light/dark theme, optional dynamic color, English/Russian strings, and RTL rendering | 21, 22 | Pending | Screenshot/accessibility/localization matrix |

## 10. Decryption and Protected Viewer

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| DEC-01 | `ACTION_PROCESS_TEXT` validates ciphertext, is read-only, and never returns plaintext to source app | 14 | Pending | Intent/instrumentation test |
| DEC-02 | IME selected-text action decrypts only selected ciphertext; fallback copies ciphertext only | 14 | Pending | InputConnection/clipboard tests |
| DEC-03 | Clipboard never receives plaintext automatically | 14, 23 | Pending | Clipboard listener/history test |
| DEC-04 | Wrong-contact, tampered, truncated, replayed, incomplete, and oversized inputs fail closed | 7, 12, 25 | Pending | Negative integration suite |
| DEC-05 | Viewer sets `FLAG_SECURE` and prevents normal screenshots | 15 | Pending | Window flag and screenshot test |
| DEC-06 | Viewer is excluded/blanked in recent-app previews | 15 | Pending | Recents instrumentation/manual evidence |
| DEC-07 | Viewer clears/closes on background, screen off, lock, timeout, and immediate-hide action | 15 | Pending | Lifecycle tests |
| DEC-08 | Plaintext selection/copy/share/notification/assistant/content-capture/autofill is disabled by default | 15, 23 | Pending | UI/system-service tests |
| DEC-09 | Secure reply opens composer for authenticated contact without plaintext intent/state transfer | 14, 15 | Pending | Intent and memory/state test |
| DEC-10 | UI explains that `FLAG_SECURE` and Accessibility restrictions are not absolute protection | 3, 15 | Pending | English/Russian security-screen review |

## 11. Plaintext, Memory, and Diagnostic Leakage

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| LEAK-01 | No plaintext in logcat, crash output, analytics, breadcrumbs, traces, or Gradle/test snapshots | 23 | Pending | Sentinel plaintext scan across runtime/build outputs |
| LEAK-02 | No full ciphertext, QR payload, private/session key, full fingerprint, Safety Number, or contact name in logs | 23 | Pending | Structured log review and sentinel tests |
| LEAK-03 | Release debug logging is disabled and user errors omit stack traces/content | 21, 23 | Pending | Release build/config/UI test |
| LEAK-04 | No plaintext in clipboard, notifications, intents, filenames, temp/cache files, normal Room tables, or recent previews | 23 | Pending | Cross-surface sentinel test |
| MEM-01 | Rust minimizes clones and zeroizes owned secret buffers where possible | 24 | Pending | Rust code review/tests |
| MEM-02 | Kotlin uses clearable arrays where possible and clears/cancels short-lived plaintext state | 24 | Pending | Kotlin/lifecycle review |
| MEM-03 | No plaintext/key in singleton, static field, or long-lived coroutine | 24 | Pending | Static analysis and lifecycle review |
| MEM-04 | JVM/UI/JNI zeroization limitations are documented without guaranteed-RAM-erasure claims | 24 | Implemented | `THREAT_MODEL.md`; UI/README review pending |

## 12. Android Permissions and Components

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| AND-01 | Manifest excludes Internet/network, Contacts, SMS, package-query, overlay, and Accessibility-service permissions | 19, 28 | Pending | Merged manifest and signed APK permissions dump |
| AND-02 | Camera is the only planned dangerous runtime permission and is requested just in time | 19 | Pending | Manifest and runtime permission test |
| AND-03 | Sensitive activities/services/providers are non-exported unless required and strictly validate callers/input | 27, 28 | Pending | Component/intent-filter review |
| AND-04 | Process-text component is exported only as Android requires and treats all input as hostile | 14, 27 | Pending | Manifest/source/fuzz review |
| AND-05 | PendingIntents, if any, are immutable/mutable only as necessary and explicit | 27 | Pending | Static manifest/source scan |
| AND-06 | Cleartext traffic is disabled even though no network capability exists | 27 | Pending | Network security/manifest review |
| AND-07 | No deep link, path traversal, unsafe file provider, ZIP extraction, or broad package visibility surface | 27 | Pending | Static and hostile-intent tests |
| AND-08 | Native libraries use supported ABI set and release hardening | 27, 30 | Pending | ELF inspection for `arm64-v8a` and test `x86_64` |

## 13. Tests and Security Tooling

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| TST-01 | Alice/Bob pairing, Safety Number, bidirectional first messages, and 1000-message sequence pass | 25 | Pending | Unit/integration report |
| TST-02 | Reorder, skip, replay, tamper, truncate, trailing data, wrong version/contact, concurrency pass | 25 | Pending | Protocol test report |
| TST-03 | Empty, long, Unicode, maximum multipart, and over-limit cases pass | 25 | Pending | Protocol/parser report |
| TST-04 | Crash matrix and restart replay tests pass | 17, 25 | Pending | Fault-injection report |
| TST-05 | Delete, re-pair, identity change, DB corruption, Keystore invalidation, StrongBox/TEE fallback pass | 25 | Pending | Storage/device report |
| TST-06 | Parser property tests and fuzzing complete without panic or unbounded allocation | 25 | Pending | Seed, duration, corpus/hash, sanitizer result |
| TST-07 | IME regression, secure composer, process-text, selection, clipboard, lifecycle, and viewer Android tests pass | 26 | Pending | Instrumentation report |
| TST-08 | Tests run on GrapheneOS without Google Play | 20, 26 | Pending | Device/build/version evidence |
| TOOL-01 | Gradle lint and unit tests pass | 27 | Pending | CI/local logs for release commit |
| TOOL-02 | Kotlin formatting/static analysis pass | 27 | Pending | ktlint/detekt or documented equivalents |
| TOOL-03 | `cargo fmt --check`, clippy with warnings denied, and Rust tests pass | 27 | Pending | Command logs |
| TOOL-04 | Dependency audit/locking/SBOM checks pass or exceptions are risk-accepted with expiry | 27 | Pending | Audit reports and lockfile review |
| TOOL-05 | Secret scan and plaintext sentinel scan pass | 23, 27 | Pending | Scanner versions/config/results |

## 14. Release Artifact and Signing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| REL-01 | Debug and release scripts are deterministic, fail closed, and do not print signing secrets | 29 | Pending | Script review and clean build |
| REL-02 | Release key is generated/stored outside Git with no password in repository or console output | 29 | Pending | Redacted location/permissions check |
| REL-03 | Signing key backup/continuity warning is documented; existing key is never overwritten | 29 | Pending | `RELEASE.md` and script test |
| REL-04 | Release APK is not debug-signed, debuggable, or test-only | 28 | Pending | `apksigner`, manifest, signing certificate evidence |
| REL-05 | `apksigner verify --verbose` succeeds | 28, 31 | Pending | Exact `dist` APK verification log |
| REL-06 | `aapt` and `apkanalyzer` permission lists contain no forbidden permission | 28, 31 | Pending | Exact `dist` APK dumps; INTERNET is a hard blocker |
| REL-07 | Exported components and intent filters pass final APK review | 27, 28 | Pending | Merged manifest/APK report |
| REL-08 | APK scan finds no Firebase, analytics, crash, ad, Play Services, test keys, or dynamic loading | 28 | Pending | Class/resource/native scan report |
| REL-09 | `dist/` contains both APKs, release SHA-256, SBOM, notices, and complete build info | 30 | Pending | Artifact inventory |
| REL-10 | Build info records commit, upstream, toolchain, SDK/NDK/Rust/crypto versions, ABI, digest, cert, and permissions without secrets | 30 | Pending | `dist/BUILD_INFO.txt` review |
| REL-11 | Release APK installs and launches, and CipherBoard can be enabled as an IME | 31 | Pending | `adb install` and device acceptance log |
| REL-12 | Release SHA-256 and certificate fingerprint are independently recomputed | 28, 30 | Pending | Two-tool comparison where practical |

## 15. UX, Localization, and User Guidance

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| UX-01 | English and Russian resources cover all user-facing text, errors, plurals, and accessibility descriptions | 21, 22 | Pending | Resource lint and bilingual review |
| UX-02 | Security screen states protections and all explicit limitations in plain language | 3, 21 | Pending | English/Russian content review |
| UX-03 | Contact/session states are distinct and understandable | 21 | Pending | UI state-machine and copy review |
| UX-04 | No stack traces, raw crypto errors, or misleading assurances are shown | 3, 21 | Pending | Negative-path UI test/string scan |
| UX-05 | Installation guide covers trusted source, SHA-256, IME enablement, Network/Sensors denial, strong lock, locked bootloader, and Accessibility risk | 20 | Pending | GrapheneOS guide review |
| UX-06 | Pair/send/decrypt/update/re-pair flows and no-history consequences are documented | 9, 18, 33 | Pending | End-to-end documentation test |
| UX-07 | High-risk guidance requires independent applied-crypto and Android-security review | 33 | Implemented | `THREAT_MODEL.md`; final report/UI review pending |

## Release Gate

Release is blocked if any acceptance-critical item remains `Pending` or merely
`Implemented`, including any of the following:

- a forbidden permission, especially `android.permission.INTERNET`;
- unsigned, debug-signed, debuggable, or test-only production APK;
- missing final-artifact manifest/signature/hash evidence;
- failing cryptographic, atomicity, replay, parser, storage, leakage, IME, or
  protected-viewer test;
- plaintext observed in a host field, clipboard, log, persistent store,
  notification, recent preview, or screenshot through normal Android APIs;
- unpinned or vulnerable crypto dependency without a documented, reviewed
  resolution;
- inability to run without Google Play or to build the required `arm64-v8a`
  artifact;
- missing GPLv3 source/notices or missing SBOM/build provenance;
- claim of independent audit when no such review occurred.

At release, archive the checklist together with the exact Git commit, APK
SHA-256, signing certificate fingerprint, tool versions, and test reports. The
statement that automated tests passed must identify the exact artifact and must
remain separate from any claim of independent audit.
