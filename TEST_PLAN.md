# CipherBoard Test Plan

Status: required verification plan. This file defines tests and evidence; it
does not claim they currently pass. Results belong in CI artifacts,
`SECURITY_REVIEW.md`, and the signed release report.

## 1. Test Policy

Each development phase is gated. A phase with a failing required test does not
advance and no failed/ignored test is relabelled as accepted without a written
risk decision. Release has no waiver for `android.permission.INTERNET`, debug
signing, `debuggable=true`, an invalid signature, or plaintext crossing the IME
boundary.

Tests use generated Alice/Bob fixtures and conspicuous random sentinels. They
never use production identities, contact names, signing credentials, or message
content. Test failures report fixed codes, hashes of random test operation IDs,
and lengths only; they do not print plaintext, full ciphertext, QR payload,
fingerprints, Safety Numbers, keys, or pickles.

Required layers:

| Layer | Purpose |
| --- | --- |
| Rust unit/integration | vodozemac wrapper, state changes, exact bytes, zeroization-facing API |
| Rust property/fuzz | arbitrary envelope/QR/inner input, limits, fragmentation invariants |
| JVM unit/Robolectric | state machines, repositories, IME gates, parsers at JNI boundary |
| Android instrumentation | real framework lifecycle, `InputConnection`, intents, storage, clipboard, windows |
| Emulator | API/locale/orientation matrix, process kill, no-Play image |
| Physical Android | camera, biometric/device credential, screen lock, Keystore behavior |
| Physical GrapheneOS | primary no-Google/Network-disabled acceptance and IME workflows |
| Static/release | dependency, manifest, APK, signing, SBOM, secret/license checks |

Unit fakes establish deterministic error coverage but cannot satisfy a
hardware/device acceptance gate.

## 2. Deterministic Fixtures and Oracles

- Fixed-seed **test-only** accounts produce golden public vectors; release code
  has no injectable RNG and fixture seeds are unmistakably non-production.
- Golden vectors cover `CBFP1`, signed `CBO1` and `CBR1`, transcript hash,
  routing tag, 60-digit Safety Number, eight-emoji indices, inner message CBOR,
  single/multipart `CB1`, and Base64url without padding.
- A second independent parser/encoder test implementation checks golden bytes;
  it is test-only and does not implement cryptographic primitives.
- Every Unicode oracle compares original and decrypted UTF-8 `ByteArray`, not
  visually normalized strings.
- Database tests inspect only encrypted rows and schema metadata. Known
  plaintext sentinels MUST be absent from the database file, WAL, SHM, files,
  preferences, cache, saved state, and backup/export archives.

## 3. Required Alice/Bob Crypto Matrix

The following table maps the 30 required cryptographic/storage scenarios.

| ID | Required scenario | Test and expected result | Layer |
| --- | --- | --- | --- |
| C01 | Initial QR pairing | A offer -> B response -> A inbound session; signed fields, expiry, single-use state and identities match | Rust integration + Android QR |
| C02 | Safety Number match | Both derive byte-identical transcript, 60 digits and emoji indices; one-bit transcript change changes outputs | Rust golden/property |
| C03 | First A -> B | A encrypts and persists; B decrypts exact bytes, commits replay/session before display | Rust/storage integration |
| C04 | First B -> A | Outbound session already advanced by pairing confirmation; first user message decrypts as normal Olm message | Rust integration |
| C05 | 1000 sequential | Alternating and one-direction sequences decrypt exactly; revisions/sequences strictly increase; no key reuse | Rust integration |
| C06 | Shuffled delivery | Deliver a supported bounded permutation; messages decrypt once and UI ordering flags are correct | Rust integration/property |
| C07 | Missing messages | Skip within and beyond library bounds; supported gap decrypts, excessive gap returns fixed error with unchanged state | Rust integration |
| C08 | Duplicate ciphertext | Second delivery is replay/missing-key error; no viewer record or state advancement | Rust + storage restart |
| C09 | One-byte corruption | Mutate every structural/Olm region; parse, digest, or MAC failure; no state mutation | Mutation/property |
| C10 | Truncated ciphertext | Truncate at every byte boundary for bounded fixtures; no panic/OOM/state mutation | Property/fuzz |
| C11 | Trailing data | Bytes after CBOR root, Base64 token suffix, and non-whitespace process-text suffix are rejected | Parser unit/fuzz |
| C12 | Unknown protocol | `CB2`, CBOR version !=1, unknown message/Olm type, required capability, or critical extension fails closed | Parser unit |
| C13 | Other contact | Swap routing tag, identities, session or contact lookup; error precedes display and does not try alternate sessions unboundedly | Rust/storage integration |
| C14 | Concurrent send | Barrier-start N sends on one contact; per-contact lock/revision serializes them, all IDs/keys unique; stale revision aborts | JVM/Rust concurrency |
| C15 | Crash before state save | Kill after native encrypt/decrypt but before DB commit; old revision remains and no output/display was published | Instrumented failpoint |
| C16 | Crash after state save | Kill after transaction commit; restart recovers exact pending send/display and never calls Olm operation again | Instrumented failpoint |
| C17 | Crash before ciphertext transfer | Kill after pending commit before `InputConnection`; restart offers exact stored bytes, no ratchet advance | Android process kill |
| C18 | Delete contact | Session/contact/pending records become inaccessible; ciphertext no longer decrypts; database contains no plaintext | Storage + device filesystem |
| C19 | Re-pair | New IDs/nonces/one-time key/transcript/routing/session; old route fails; local name policy is explicit | Integration + UI |
| C20 | Identity change | Reinstall/reset peer fixture yields `KEY_CHANGED`; send/decrypt blocked until new physical pairing | JVM + device lifecycle |
| C21 | Unicode classes | Russian, English, combining marks, emoji/ZWJ, Arabic/RTL, CJK, math, newlines, NUL, bidi and zero-width code points round-trip byte-exactly | Parameterized/property + UI |
| C22 | Empty message | Empty UTF-8 body is valid, encrypts/decrypts, displays empty-state without confusing it with failure | Rust + UI |
| C23 | Very long message | Exactly 262,144 UTF-8 bytes succeeds if selected profile fits; +1 byte fails before ratchet mutation | Boundary/property |
| C24 | Maximum parts | Exactly 128 consistent parts reassemble out of order within aggregate limit | Parser/property |
| C25 | Too many parts | Count 129, part 129, oversized aggregate, and fragmenter result >128 are rejected before allocation/decrypt | Parser/fuzz |
| C26 | Replay after restart | Commit receive, kill process, reopen vault, redeliver; persisted ledger/ratchet reject it | Android/storage restart |
| C27 | Corrupted local DB | Flip nonce/ciphertext/AAD/revision/truncate DB copy; fail closed as vault/session error, never reset silently | Storage mutation/device |
| C28 | Keystore invalidation | Invalidate auth/wrapping key; vault locks, secrets remain unreadable, explicit destructive recovery/re-pair only | Physical device |
| C29 | StrongBox unavailable | Inject exception for exhaustive unit test and use an actual no-StrongBox configuration; TEE key is created and level shown honestly | JVM + physical device |
| C30 | TEE-only operation | Pair, restart, send and decrypt with confirmed TEE-backed key and no StrongBox; no software fallback claim | Physical device |

For C06/C07, tests use vodozemac's published high-level limits (five receiving
chains, 40 skipped keys per chain, maximum forward gap 2000) and test exact
boundary values. They do not claim unlimited reordering.

## 4. Atomicity and Recovery Fault Matrix

Production builds omit failpoints. A test-only injected crash process exits
without cleanup at each labelled boundary. The database is reopened in a fresh
process and invariants are checked from durable state.

### Send failpoints

| Failpoint | Durable expectation | Publication expectation |
| --- | --- | --- |
| Before session load | no change | nothing sent |
| After load/before encrypt | no change | nothing sent |
| After encrypt/before transaction | revision unchanged; no pending | nothing sent |
| During transaction before commit | full rollback | nothing sent |
| Immediately after commit | revision +1 and exact `READY_TO_COMMIT` | nothing sent yet |
| After capability mint | same pending; capability gone on process death | nothing sent yet |
| Before `commitText` | same pending | nothing sent |
| Host returns false | same pending; one capability consumed | no accepted insertion |
| Host accepts/before status commit | pending marked unknown on recovery | host may contain exact ciphertext; never re-encrypt |
| After `HOST_ACCEPTED` commit | advanced state and accepted status | exact ciphertext only |

The host recording double returns configurable true/false, kills the process at
method entry/return, and records every invoked `InputConnection` method. An
ambiguous host acknowledgement is not described as exactly-once delivery;
explicit retry uses identical bytes and receiver replay protection.

### Receive failpoints

| Failpoint | Durable expectation | Display expectation |
| --- | --- | --- |
| During parse/reassembly | no session/replay change | nothing shown |
| After decrypt/before transaction | old revision; no replay/pending | nothing shown |
| During transaction before commit | full rollback | nothing shown |
| Immediately after commit | revision +1, replay ID, encrypted `READY_TO_DISPLAY` | nothing shown yet |
| During pending-display unwrap | state remains advanced; recoverable pending or fixed corruption error | no Olm re-decrypt |
| After view render | advanced state; pending exists until close | protected viewer only |
| During close/delete | restart locks then deletes/expires pending under no-history policy | never host/clipboard |

Inbound pre-key tests additionally assert that account pickle consumption,
session creation, replay ID, and pending display commit in the same transaction.

## 5. Parser, Property, and Fuzz Tests

### 5.1 Generators

Property generators vary canonical and non-canonical CBOR, duplicate/unknown
keys, nesting, declared lengths, part order, duplicate/missing parts, IDs,
digests, Olm type, flags, Base64 alphabet/padding, whitespace boundaries, UTF-8
validity, and all size limits. Valid-message properties are:

- encode -> parse -> encode returns identical canonical bytes;
- fragment -> arbitrary permutation -> reassemble returns exact Olm bytes;
- Universal/SMS fragment tokens respect their independent size caps;
- a valid optional unknown extension is ignored, while a critical/unknown core
  field is rejected;
- parse errors never mutate session/storage or expose partial plaintext; and
- allocation is bounded by the input and configured aggregate limits.

### 5.2 Fuzz targets

Separate native targets cover Base64 tokenization, CB1 CBOR, offer, response,
inner payload, fragment collector, and JNI length/error conversion. Corpus seeds
include every golden vector and every one-byte-short boundary. Each target runs
under ASan/UBSan on a supported host in scheduled CI and a time-bounded smoke
run on every release candidate.

Parser fuzzing is isolated from vodozemac crypto. Production or crypto tests
MUST NOT compile vodozemac with `cfg(fuzzing)`, because that configuration can
disable MAC verification. Release scripts scan Rust flags and artifacts for it.

Success criteria: no panic, abort, out-of-bounds access, excessive allocation,
hang, or acceptance outside the grammar. Any minimized crash becomes a checked
regression fixture.

## 6. Android IME and UI Matrix

### 6.1 Ordinary HeliBoard regression

On API 30, 34, 36 and the current GrapheneOS API, test English/Russian layout
selection, language switch, shift/caps, autocorrection, gesture input where
supported, numbers, symbols, emoji search/recents, combining Unicode, multiline
enter, delete/selection, landscape, one-handed mode, light/dark themes, dynamic
color option, large fonts, and IME restart. Test against a local host app with
single-line, multiline, SMS-like, Telegram-like, RTL, and password
`EditorInfo` configurations. Ordinary behavior may retain upstream features;
secure-mode isolation must not weaken when those preferences are enabled.

### 6.2 Secure composer and `InputConnection` defense

Use a `RecordingInputConnection` that records arguments to every method,
including `commitText`, `setComposingText`, `setComposingRegion`,
`commitCompletion`, `commitCorrection`, `commitContent`, `sendKeyEvent`, batch,
private command, editor action, cursor/selection, extracted/surrounding reads,
and clipboard fallbacks.

For a unique plaintext sentinel, exercise tap, long-press, suggestion, gesture,
emoji, composition, space/enter, delete, language switch, orientation, editor
restart, toolbar actions, app completion, and race entry/exit. Expected:

- the sentinel appears only in the private composer view/memory lifetime;
- zero host-mutating calls contain plaintext or a derived composing fragment;
- personal learning, emoji recents, user dictionary and clipboard history get
  no secure entry;
- no surrounding host text is requested while composing;
- only a one-use capability can call `commitText`, with exact persisted `CB1`;
- false/stale editor/capability/token/bytes are rejected;
- no printable key-event or alternate `InputConnection` path bypasses the gate;
- successful accepted insertion wipes composer and leaves only ciphertext; and
- password fields show the warning and never auto-open/auto-commit.

A static test enumerates direct `getCurrentInputConnection` and
`InputConnection` mutation calls and compares them with a reviewed allowlist.
Adding an unmediated call fails CI.

### 6.3 Decryption entry points

For `ACTION_PROCESS_TEXT`, test one/multipart valid input, read-only and
editable callers, missing/incorrect MIME, null/oversize extras, bad component
launch, trailing text, replay, wrong contact, locked vault, cancelled auth, and
background launch restrictions. Expected result is never plaintext; source
selection is unchanged and no plaintext extra/result leaves the activity.

For IME selection, test `getSelectedText` success/null/timeout/oversize and
malicious styled spans. Spans are discarded and only bounded plain ciphertext
is parsed. Clipboard fallback is manual and ciphertext-only; after reading it,
CipherBoard never overwrites clipboard with plaintext. Reply carries only a
random internal contact ID after viewer data is cleared.

### 6.4 Protected viewer lifecycle

Test `FLAG_SECURE`, `excludeFromRecents`, no history state, no notification,
non-selectable text, no copy/share/Assistant/content-capture/autofill, immediate
hide, configured timeout, home/recent/back, task switch, screen off/on, lock,
rotation, multi-window attempt, process death, and reply. Screenshot/screen
record output must be blocked/blank according to the OS and the recent-app
thumbnail must not contain the sentinel. A `UiAutomation` accessibility dump
must not expose protected plaintext; non-secret controls retain localized
labels.

### 6.5 Localization and layout

Run screenshot/layout assertions for `en` and `ru`, light/dark, portrait/
landscape, font scales 1.0/1.3/2.0, display scaling, and pseudo-RTL. Verify all
product strings are resources, Russian has no accidental English fragments,
plurals/number grouping are correct, touch targets and content descriptions are
present for non-secret actions, no text overlaps/clips, and secret content is
deliberately excluded from TalkBack/accessibility export.

## 7. Storage, Keystore, and Lifecycle Tests

- Verify the Keystore alias is AES-256-GCM, non-exportable, user-authenticated,
  and reports the expected StrongBox or TEE level. Software/unknown fails closed
  under release policy and is labelled honestly.
- Exercise immediate/30-second/1-minute/5-minute leases with monotonic elapsed
  time, manual lock, app background, screen lock, reboot, first unlock, and
  process death. Default is one minute.
- Keep the device locked after reboot: ordinary keyboard renders from the DE
  allowlist; every vault operation remains unavailable and CE files unopened.
- Inspect DE/CE trees with test-only `run-as`: secret sentinels are absent from
  DE, preferences, filenames, files and cache. Encrypted blobs do not contain
  sentinel subsequences; nonce uniqueness holds across stress creation.
- Attempt upstream settings backup, Android backup/data extraction, app clone,
  and restore. No identity, contact, session, replay, pairing, pending, DEK, or
  wrapped-key record is transferable.
- Test invalid AEAD tag, nonce, AAD record ID/type/revision, missing wrapped
  DEK, wrong alias, credential reset, and key invalidation. All fail closed with
  fixed user-safe states and no silent identity/session reset.
- Delete contact/vault and scan DB/WAL/SHM after checkpoint. Verify logical
  inaccessibility and document that flash-level physical erasure is not proven.

## 8. Pairing and Contact UI Tests

Use both generated QR images and two live cameras. Test offer creation,
camera-on-demand permission grant/deny/permanent deny, scan cancel, response,
Safety Number/emoji comparison, explicit verified/unverified decisions,
rename, fingerprint display/export, reverify, delete, session destroy, re-pair,
expired/cancelled offer, duplicate import, duplicate response, wrong pairing
ID, bad signatures, capability downgrade, identity change, and concurrent
offers.

QR images and payloads must not appear in screenshots after leaving, recent
previews, logs, cache, media store, or analytics. Owner/contact local names are
absent from decoded protocol fixtures. No system Contacts permission or API is
used. There is no UI/intent for remote pairing in v1.

## 9. Leakage and Logging Tests

Inject a fresh high-entropy sentinel through composer and decrypt viewer, then:

1. capture logcat before/during/after success, every error, rotation, kill and
   crash; search plaintext, full ciphertext/QR, keys, full fingerprints, Safety
   Number and contact name;
2. inspect app CE/DE files, databases, WAL/SHM, shared preferences, cache,
   no-backup, saved-state, tombstone-accessible test output, and Gradle reports;
3. inspect system clipboard/keyboard history, notification shade/history,
   recent tasks, screenshot, accessibility hierarchy, autofill and content
   capture test services;
4. inspect intents/bundles/results with an adversarial caller and lifecycle
   instrumentation; and
5. scan release source/resources/native strings for content-bearing log format
   paths and forbidden debug facilities.

The test passes only when plaintext is absent everywhere except the active
private composer/viewer memory and pixels allowed by the design. Absolute JVM/
GPU RAM erasure is not asserted.

## 10. Static Analysis and Dependency Gates

Required commands, adapted to PowerShell/Gradle wrapper names on Windows:

```text
./gradlew lint
./gradlew test
./gradlew connectedCheck
./gradlew ktlintCheck          # or the pinned equivalent
./gradlew detekt               # or the pinned equivalent
cargo fmt --check --manifest-path crypto-core/native/Cargo.toml
cargo clippy --locked --all-targets --manifest-path crypto-core/native/Cargo.toml -- -D warnings
cargo test --locked --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock
```

Release additionally requires:

- Gradle dependency locking/verification and committed `Cargo.lock`;
- SBOM generation for Gradle, Rust and packaged native components;
- OSV/cargo audit review with no untriaged applicable vulnerability;
- ktlint/detekt/Android lint with no release error;
- secret scan of tracked and distribution files;
- license compatibility/notices verification;
- source/dependency scan for network clients, localhost, Firebase, Play
  services, analytics, crash, ads, WebView, reflection/dynamic loaders;
- manifest review of permissions, exported components, intent filters,
  providers, PendingIntent mutability, deep links, backup/data extraction,
  cleartext policy, and `usesCleartextTraffic`;
- path traversal/ZIP import/QR and styled-span parser tests;
- native ABI and hardening inspection (arm64-v8a release, x86_64 test;
  PIE/NX/RELRO/stack protection as toolchain applicable, stripped symbols,
  panic abort, no unexpected `.so`); and
- release Rust flag scan proving absence of `cfg(fuzzing)`.

## 11. APK and Release Verification

Run independent tools against the exact APK copied to `dist/`:

```text
aapt dump permissions CipherBoard-<version>-release.apk
apkanalyzer manifest permissions CipherBoard-<version>-release.apk
apksigner verify --verbose --print-certs CipherBoard-<version>-release.apk
sha256sum CipherBoard-<version>-release.apk
```

Also dump the complete manifest and certificate, install with `adb install`,
launch settings, enable/select the IME, and execute a smoke pair/send/decrypt.
Checks require:

- no `INTERNET`, `ACCESS_NETWORK_STATE`, Contacts, SMS, query-all, overlay, or
  accessibility permission; camera is the only pairing runtime permission;
- no Firebase/analytics/crash/ads/Play Services classes/resources/native code;
- `allowBackup=false`, secret-excluding extraction rules, no WebView/dynamic
  loading, and no cleartext traffic;
- sensitive activities/providers are non-exported; exported components have
  system permission or strict external-input validation;
- `debuggable=false`, `testOnly=false`, release key rather than Android debug
  key, valid v2/v3 signing as supported, correct package/product name;
- only intended `arm64-v8a` release native libraries (and separately x86_64 in
  test artifacts); and
- SHA-256, signing certificate fingerprint, permissions, versions, ABI and git
  revision in `BUILD_INFO.txt` match independent tool output.

Any INTERNET occurrence, debug certificate, signature failure, plaintext test
key, or sensitive unvalidated exported component blocks release.

## 12. Device-Only Acceptance Gates

The following cannot be signed off by Robolectric, JVM mocks, static analysis,
or the existing Play Store emulator. Evidence must identify OS build, device,
APK SHA-256, and test date without recording device identifiers or secrets.

| Gate | Required physical evidence |
| --- | --- |
| D01 Two-party flow | Two devices perform reciprocal live-camera QR, compare values, send both ways, reorder and replay |
| D02 GrapheneOS/no Google | Current supported GrapheneOS on Pixel, no Sandboxed Google Play, full first-run/IME/process-text flow |
| D03 Network off | GrapheneOS Network permission disabled; app continues all flows; manifest independently lacks INTERNET |
| D04 StrongBox | Physical Pixel reports StrongBox for wrapping key and completes auth, restart, pair/send/decrypt |
| D05 TEE fallback | Physical/configuration with StrongBox unavailable reports TEE (not software) and completes the same flow |
| D06 Authentication | Real strong biometric and device credential success/cancel/lockout; lease timeouts and manual lock |
| D07 Invalidation | Controlled credential/key invalidation produces unrecoverable-vault state and re-pair recovery, no silent key creation |
| D08 Direct boot | Reboot and use IME before first unlock; ordinary keyboard works, vault data/contacts remain inaccessible |
| D09 Window protection | Hardware/system screenshot, screen recording, recents, screen-off and lock tests show no plaintext capture |
| D10 Accessibility | Test Accessibility service/UiAutomation cannot extract protected plaintext; warning explains malicious services remain out of scope |
| D11 Host interoperability | AOSP SMS draft and local Telegram-like single/multiline hosts receive only exact ciphertext; selection decrypt leaves source unchanged |
| D12 Camera permission | Camera is unrequested until Scan, grant/deny/revoke paths work fully offline |
| D13 Destructive lifecycle | App data clear/reinstall changes identity and peer shows critical key change/pairing required |
| D14 Locked-device theft model | With device locked/rebooted, CE vault unavailable; DB copy available to test harness contains only authenticated ciphertext |

At least one non-Play AOSP `x86_64` emulator is also required for repeatable
`connectedCheck`. It supplements but does not replace GrapheneOS device gates.

## 13. Phase Gates

| Phase | Must be green before proceeding |
| --- | --- |
| 0 Research | pinned upstream/crypto evidence, environment record, ADR, Rust-Android smoke link |
| 1 HeliBoard | upstream unit/lint build, English/Russian/emoji regression, branding/package tests, forbidden-permission scan |
| 2 Crypto | C01-C27 applicable host tests, golden vectors, property/fuzz smoke, Rust fmt/clippy/test/audit |
| 3 Storage | atomic fault matrix, encryption/leak scans, backup/direct-boot separation, fake and real Keystore baseline |
| 4 Pairing | signed QR negative matrix, two-device transcript/Safety match, camera permission and single-use tests |
| 5 Secure keyboard | recording-connection bypass suite, ordinary regression, password warning, ciphertext-only commit/recovery |
| 6 Decryption | both entry points, viewer lifecycle, replay/reorder, no result/clipboard/plaintext leakage |
| 7 UX/localization | en/ru, themes, font/orientation/RTL/accessibility and understandable error-state review |
| 8 Hardening | full fuzz/static/dependency/native/log/manifest/security review; all findings resolved or release-blocked |
| 9 Release | signed APK/APK tool agreement, SBOM/notices/build info, D01-D14, install/update smoke, dist hashes |

## 14. Release Evidence Package

Archive without secrets: command versions, test XML summaries, fuzz corpus
hashes and duration, lint/static reports, merged manifest, aapt/apkanalyzer
permission output, apksigner certificate output, SBOM, dependency locks/audit,
device-gate checklist, APK SHA-256, git/upstream/vodozemac revisions, and resolved
`SECURITY_REVIEW.md`. Never archive plaintext fixtures, private identities,
release keystore/password, full QR captures, or local contact data.

A release report distinguishes **passed**, **failed**, **blocked (no device)**,
and **not run**. Missing physical GrapheneOS, StrongBox, TEE, biometric,
invalidation, direct-boot, screenshot, or two-camera evidence remains a blocker;
it is not converted into a pass by unit mocks.
