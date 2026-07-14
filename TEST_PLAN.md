# CipherBoard Test Plan

Status: required verification plan. This file defines tests and records only the
explicitly identified evidence snapshot below. Artifact-specific results belong
in CI artifacts, `SECURITY_REVIEW.md`, generated `BUILD_INFO.txt`, and the signed
release report.

## 1. Test Policy

Each development phase is gated. A phase with a failing required test does not
advance and no failed/ignored test is relabelled as accepted without a written
risk decision. Release has no waiver for `android.permission.INTERNET`, debug
signing, `debuggable=true`, an invalid signature, forbidden `INTERNET` or
`REQUEST_INSTALL_PACKAGES`, or plaintext crossing the IME boundary.

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

### 1.1 Current evidence snapshot (not an independent audit)

As of 2026-07-14, stored/reported local evidence is:

| Scope | Result | Limitation |
| --- | --- | --- |
| `crypto-core/native` and JNI | 43 native and 3 JNI tests passing; format, Clippy and Cargo audit passing | no independent oracle/audit or archived exact-release log; final wire decisions remain |
| repository Android unit gate | full `app`, `crypto-core`, `pairing`, and `secure-storage` debug unit tasks pass | JVM/fakes; not framework/camera/real-Keystore evidence; two inherited regressions are explicitly ignored with issue-specific reasons |
| repository Android lint gate | app/library module release lint tasks pass on current worktree | rerun and archive for the final commit/artifact |
| transport cargo-fuzz | pinned ASan/libFuzzer run completed 236,453 inputs in 61 seconds with zero crashes/timeouts/artifacts | bounded local run; not long-duration, multi-platform, pairing, inner-codec, or JNI evidence |
| dependency vulnerability scan | official SHA-pinned OSV-Scanner v2.4.0 scanned all 255 SBOM packages against fresh offline Maven/crates.io DBs; exit 0/zero findings, including the pre-public local signed-candidate run | repeat and archive against the final public release SBOM |
| offline licenses | unit test requires GPL/Apache/BlueOak/BSD/CC/notices/provenance assets to exist and be nonempty | final APK asset/manual completeness review pending |
| pairing/contact | state-machine tests cover one-shot state, bounded orphan cleanup, duplicate/expiry and blocking identity change | no live-camera/permission/pairing E2E or pairing-specific process-kill evidence |
| pending recovery/IME handoff | 2 store close/reopen atomicity tests plus 3 debug-only remote-process SIGKILL tests pass; unit tests cover `READY` -> `COMMIT_UNCERTAIN`, no automatic retry, exact live-connection scope, nullable Binder tokens and local draft routing | no failpoint inside individual SQLite statements or kill immediately around real `commitText()` acknowledgement |
| v0.3 embedded decrypt controls | targeted tests pass for bounded ciphertext clipboard input, drawing-only/first-draw behavior, one-shot unlock, reply draft wipe, race-safe worker-result ownership, render-time Vault expiry, background cancellation and secure-IME lifecycle | manual API 36 English/Russian landscape/font-2.0 covers locked Encrypt and idle Decrypt only; no paired-contact decrypt, biometric, process-kill-at-first-draw or physical GrapheneOS evidence |
| v0.4 word presentation source | pinned dictionary, Compact/Russian/English, malformed/limit/property, real Olm, JNI, pending-state and settings tests pass; fuzz uses nine reviewed seeds | rerun and archive every gate on the exact release commit; no paired-contact messenger or physical GrapheneOS E2E evidence |
| Android instrumentation | `:app:connectedDebugAndroidTest --no-configuration-cache` passes 7/7, zero failed/skipped, on API 36 x86_64 AOSP no-Play | targeted process-text/viewer/clipboard/vault scope; no full IME/private-panel/live-camera E2E |
| debug Home/UI smoke | current APK installs/launches; Message format remains reachable with a locked Vault at font scale 2.0; the Russian settings screen has no status-bar overlap and scrolls in portrait/landscape at font scale 2.0 | targeted Home/settings only; no full screen/theme/RTL matrix and no ordinary IME input claim |
| signed release candidate | a clean pre-public local pipeline produced a non-debug-signed APK and passed scripted signature, permission, APK-policy, SBOM/vulnerability, and artifact-hash gates | its evidence bundle is local, untracked, and unpublished; rebuild and publish new evidence for the final public tag; physical install acceptance is not claimed |
| GrapheneOS/physical devices | not run | D01-D14 remain residual validation prerequisites before high-risk use, not demonstrated critical code defects |

Independent protocol review should validate the exact documented routing,
capability, inner-binding, assembly-integrity, 192-KiB Compact limit and 32-KiB
word-presentation limit decisions. This is residual assurance work, not a currently demonstrated code
defect. The numeric Safety Number and word code derive from one transcript. New
sends use universal fragmentation; legacy 48-byte SMS-profile fixtures remain a
receive-compatibility test only.

## 2. Deterministic Fixtures and Oracles

- Fixed-seed **test-only** accounts produce golden public vectors; release code
  has no injectable RNG and fixture seeds are unmistakably non-production.
- After the final schema decision, golden vectors cover fingerprint export,
  signed `CBO1` and `CBR1`, offer/transcript hash, routing tag, the approved
  numeric and short comparison renderings, inner message CBOR,
  single/multipart `CB1`, Base64url without padding, and exact compact/Russian/
  English presentation vectors. Current Rust produces
  the provisional 80-digit Safety Number and eight-word code from one hash.
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
| C02 | Safety Number match | Both derive a byte-identical transcript hash, 80-digit Safety Number and eight-word code; physical users see the same values | Rust golden/property + device |
| C03 | First A -> B | A encrypts and persists; B decrypts exact bytes, commits replay/session before display | Rust/storage integration |
| C04 | First B -> A | Outbound session already advanced by pairing confirmation; first user message decrypts as normal Olm message | Rust integration |
| C05 | 1000 sequential | Alternating and one-direction messages decrypt exactly; ratchet revisions advance and no key is reused; add authenticated sequence assertions only if the final inner schema includes them | Rust integration |
| C06 | Shuffled delivery | Deliver a supported bounded permutation; every message decrypts once and no state rolls back | Rust integration/property |
| C07 | Missing messages | Skip within and beyond library bounds; supported gap decrypts, excessive gap returns fixed error with unchanged state | Rust integration |
| C08 | Duplicate ciphertext | Second delivery is replay/missing-key error; no viewer record or state advancement | Rust + storage restart |
| C09 | One-byte corruption | Mutate every structural/Olm region; parse, digest, or MAC failure; no state mutation | Mutation/property |
| C10 | Truncated ciphertext | Truncate at every byte boundary for bounded fixtures; no panic/OOM/state mutation | Property/fuzz |
| C11 | Trailing data | Bytes after CBOR root, Base64 token suffix, and non-whitespace process-text suffix are rejected | Parser unit/fuzz |
| C12 | Unknown protocol | `CB2`, CBOR version !=1, unknown message/Olm type, required capability, or critical extension fails closed | Parser unit |
| C13 | Other contact | Swap routing tag, identities, session or contact lookup; error precedes display and does not try alternate sessions unboundedly | Rust/storage integration |
| C14 | Concurrent send | Barrier-start N sends on one contact; per-contact lock/revision serializes them, all IDs/keys unique; stale revision aborts | JVM/Rust concurrency |
| C15 | Crash before state save | Kill after native encrypt/decrypt but before DB commit; old revision remains and no output/display was published | Instrumented failpoint |
| C16 | Crash after state save | Before publication boundary, restart recovers exact `READY` send/display state without another Olm operation; after `COMMIT_UNCERTAIN`, it reports delivery unknown and cannot auto-retry | Instrumented failpoint |
| C17 | Crash before ciphertext transfer | Kill before and after the durable `COMMIT_UNCERTAIN` transition; `READY` remains single-claimable, while uncertain state is never automatically inserted | Android process kill |
| C18 | Delete contact | Session/contact/pending records become inaccessible; ciphertext no longer decrypts; database contains no plaintext | Storage + device filesystem |
| C19 | Re-pair | New IDs/nonces/one-time key/transcript/routing/session; old route fails; local name policy is explicit | Integration + UI |
| C20 | Identity change | Reinstall/reset peer fixture yields `KEY_CHANGED`; send/decrypt blocked until new physical pairing | JVM + device lifecycle |
| C21 | Unicode classes | Russian, English, combining marks, emoji/ZWJ, Arabic/RTL, CJK, math, newlines, NUL, bidi and zero-width code points round-trip byte-exactly | Parameterized/property + UI |
| C22 | Empty message | Empty UTF-8 body is valid, encrypts/decrypts, displays empty-state without confusing it with failure | Rust + UI |
| C23 | Very long message | Core accepts exactly 196,608 plaintext bytes and rejects +1 before mutation; embedded Private draft accepts at most 32,768 UTF-16 code units and rejects the next edit without unbounded UI/wipe work | Boundary/property + UI |
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

### 4.1 Recorded Android fault evidence

On 2026-07-13 the API 36 x86_64 `CipherBoard_API_36_AOSP` no-Play emulator ran
`:app:connectedDebugAndroidTest --no-configuration-cache`: 7 tests passed, 0
failed and 0 were skipped. Two tests close/reopen the real vault store and
assert outbound pending ciphertext plus inbound revision/replay conflict state.
Three more launch a debug-only remote `:fault` process and use actual
`Process.killProcess`/SIGKILL:

- before outbound commit: old revision and no pending operation survive;
- after outbound commit but before handoff: advanced revision and exact pending
  ciphertext survive; and
- after inbound commit: advanced revision, replay marker and encrypted pending
  display survive.

The debug fixture is declared only in the debug manifest/source set and is not
packaged in release. These tests do not kill between individual SQL statements
inside a transaction and do not cover the ambiguous instant around a real host
`InputConnection.commitText()` acknowledgement.

### 4.2 Required boundary matrix

Production builds omit failpoints. The current debug-only remote process covers
the three boundaries listed above. Completing the matrix requires test-only
injection at every remaining labelled boundary, process exit without cleanup,
and durable-state checks after reopening the database.

### Send failpoints

| Failpoint | Durable expectation | Publication expectation |
| --- | --- | --- |
| Before session load | no change | nothing sent |
| After load/before encrypt | no change | nothing sent |
| After encrypt/before transaction | revision unchanged; no pending | nothing sent |
| During transaction before commit | full rollback | nothing sent |
| Immediately after commit | revision +1 and exact encrypted pending-outbound row in `READY` | nothing sent yet |
| After one-shot claim | same `READY`; process-local claim consumed on death | nothing sent yet |
| After durable publication transition/before `commitText` | exact pending is `COMMIT_UNCERTAIN` | insertion may or may not follow; never auto-retry |
| Host returns false or throws | `COMMIT_UNCERTAIN` remains | host acceptance is unknown; never auto-retry |
| Host accepts/before pending deletion | `COMMIT_UNCERTAIN` remains on recovery | host may contain exact ciphertext; report unknown instead of retrying |
| After pending deletion | advanced state and no pending | exact ciphertext only |

The host recording double returns configurable true/false, kills the process at
method entry/return, and records every invoked `InputConnection` method. An
ambiguous host acknowledgement is not described as exactly-once delivery. The
test must prove `COMMIT_UNCERTAIN` cannot be claimed by automatic or ordinary
retry APIs. A user can inspect the host field; receiver replay protection is a
last line of defense, not permission to duplicate transport text.

### Receive failpoints

| Failpoint | Durable expectation | Display expectation |
| --- | --- | --- |
| During parse/reassembly | no session/replay change | nothing shown |
| After decrypt/before transaction | old revision; no replay/pending | nothing shown |
| During transaction before commit | full rollback | nothing shown |
| Immediately after commit | revision +1, replay ID, encrypted `READY_TO_DISPLAY` | nothing shown yet |
| During pending-display unwrap | state remains advanced; recoverable pending or fixed corruption error | no Olm re-decrypt |
| Abandon before render acknowledgement | exact-ciphertext-bound encrypted pending remains | temporary plaintext wiped; exact retry may reopen |
| After view render | advanced state; pending exists until close | protected viewer only |
| During close/delete after render | delete is idempotent; restart never invokes Olm decrypt for the same message | never host/clipboard |

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
- every new send uses universal fragmentation, while legacy SMS-profile `CB1`
  fixtures remain accepted by receive;
- compact -> Russian/English Base4096 -> compact round trips recover the exact
  ordered canonical `CB1` parts;
- presentation selection affects output only: all receivers auto-detect all
  three formats without matching the sender's local setting;
- a valid optional unknown extension is ignored, while a critical/unknown core
  field is rejected;
- parse errors never mutate session/storage or expose partial plaintext; and
- allocation is bounded by the input and configured aggregate limits.

### 5.2 Fuzz targets

The implemented `crypto-core/native/fuzz` package pins cargo-fuzz/libFuzzer and
compiles the production envelope/presentation/error source directly, without
pulling Olm cryptographic primitives into the fuzz binary. Its
`transport_parser` target covers arbitrary UTF-8 compact and word-like text,
arbitrary decoded CBOR bytes wrapped in strict Base64url, valid envelope round
trips, and valid Russian/English word presentation round trips. Reviewed compact,
binary, arbitrary-word, English-word, and Russian-word seeds are checked in;
generated corpus and artifacts are ignored.

The recorded 2026-07-14 ASan run executed 236,453 inputs in 61 seconds with zero
crashes, zero timeouts and zero artifacts. It used nine checked-in seeds,
`max_len=393216`, and reached 1,141 coverage counters / 3,089 features. Future
targets still must cover offer/response, inner payload, fragment collection and
JNI length/error conversion. Longer scheduled and release-candidate campaigns
must archive toolchain, duration, corpus hash, sanitizer configuration and
minimized failures.

Dedicated presentation tests MUST pin both generated dictionary SHA-256 values
and assert exactly 4096 unique lowercase tokens of 4--10 letters. They cover
tag-first checksum mutation, wrong version/alphabet/flags, unknown or mixed
words, nonzero tail padding, truncation, extra words, reordered canonical parts,
inconsistent length/count, the 48-KiB decoded-wrapper limit, 32,768-word limit,
384-Ki UTF-16 Android boundary, and allocation-safe error mapping through JNI.
Real paired Olm sessions also encrypt and decrypt an initial 32-KiB plaintext
through each word alphabet, proving the UI cap fits the wrapper instead of
relying only on an estimate. Separate regressions reverse multipart Compact
Universal and legacy SMS-profile fixtures and require canonical-order recovery.
The checksum test must state that it is not authentication; a recomputed wrapper
still reaches canonical `CB1` and Olm/AEAD validation.

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

### 6.2 Embedded Private panel and `InputConnection` defense

Use a `RecordingInputConnection` that records arguments to every method,
including `commitText`, `setComposingText`, `setComposingRegion`,
`commitCompletion`, `commitCorrection`, `commitContent`, `sendKeyEvent`, batch,
private command, editor action, cursor/selection, extracted/surrounding reads,
and clipboard fallbacks.

For a unique plaintext sentinel, exercise tap, long-press, suggestion, gesture,
emoji, composition, space/enter, delete, language switch, orientation, editor
restart, toolbar actions, app completion, and race entry/exit. Expected:

- the sentinel appears only in the embedded Private panel/view memory lifetime;
- zero host-mutating calls contain plaintext or a derived composing fragment;
- personal learning, emoji recents, user dictionary and clipboard history get
  no secure entry;
- no surrounding host text is requested while composing;
- only a one-use typed claim can call `commitText`, after the pending state
  became `COMMIT_UNCERTAIN`; the exact persisted canonical `CB1` parts and
  selected presentation must regenerate the validated delivery text;
- false/stale editor/claim/bytes and any different live `InputConnection` are
  rejected even when the client Binder token and editor metadata match;
- no printable key-event or alternate `InputConnection` path bypasses the gate;
- successful accepted insertion leaves ciphertext only in the host while the
  plaintext remains visible in the panel until Clear/Close/field change;
- explicit clear/close, host package/UID/field/connection change, screen lock and IME
  destruction wipe the local draft best effort;
- a false return/exception/crash after `COMMIT_UNCERTAIN` cannot auto-retry;
- the IME window has `FLAG_SECURE` only while Private mode is active; and
- password fields show the warning and never auto-open/auto-commit.

Switch the panel repeatedly between Encrypt and Decrypt. Expected:

- entering Decrypt hides the ordinary key wrapper and suggestion strip, while
  no software-key or host-mutating path becomes available;
- returning to Encrypt wipes received plaintext and its reply capability before
  restoring the keys and the local draft editor;
- orientation, input-view recreation, host-scope loss and screen-off cancel
  parse/decrypt work and close every stale success result; and
- no decrypted text is transferred into the outbound draft or host editor.
- the secure-panel root and every interactive descendant reject touches marked
  `FLAG_WINDOW_IS_OBSCURED`, including dynamically created contact rows.

Run a physical-keyboard sentinel separately. Android may dispatch hardware key
events directly to the focused host view, so the expected product behavior is
an explicit unsupported/warning state, never a claim that those characters are
captured by the Private draft. Private composition uses the on-screen keys.

A static test enumerates direct `getCurrentInputConnection` and
`InputConnection` mutation calls and compares them with a reviewed allowlist.
Adding an unmediated call fails CI.

### 6.3 Decryption entry points

For `ACTION_PROCESS_TEXT`, test one/multipart valid input, read-only and
editable callers, missing/incorrect MIME, null/oversize extras, bad component
launch, trailing text, replay, wrong contact, locked vault, cancelled auth, and
background launch restrictions. Expected result is never plaintext; source
selection is unchanged and no plaintext extra/result leaves the activity.

For the primary embedded flow, copy one complete compact, Russian-word, or
English-word ciphertext from Telegram-like, SMS-like, email-like and multiline
fixtures, open the shield, select Decrypt, and press **Paste and decrypt**. Test
null, empty, non-text, multiple-item, oversize, malformed, multipart-incomplete,
replay, wrong-contact and styled clipboard inputs. Reading must occur only after
the explicit button action, auto-detect the presentation with the same bounded
unstyled-ciphertext grammar as the viewer, and leave the original ciphertext
clip unchanged. The ordinary keys stay hidden throughout Decrypt mode and no
plaintext reaches the host `InputConnection`.

For send presentation, verify the Message format screen offers only **Compact**,
**Russian words**, and **English words**; the old SMS transport selector is not
present. For each setting, assert encryption calls the universal core mode,
durably stores canonical parts plus the versioned presentation enum before
`commitText()`, verifies deterministic exact reconstruction, and never
re-ratchets when rendering the same pending ciphertext. Verify Compact can be
read by the previous release and that 0.4 reads captured legacy compact fixtures
from both old Universal and SMS profiles. A word message must fail clearly on an
older peer; no silent fallback or per-contact negotiation is implied.

Test the unlock boundary separately: only a newly issued process-local token
may activate the non-exported unlock activity; activation and completion are
one-shot; duplicate, cancelled, timed-out and unknown tokens fail closed. The
Intent contains the token only, never ciphertext or plaintext. A successful
callback still requires the exact metadata-matching host return before one
live-connection rebind, and `decryptUnlocked()` must return `VAULT_LOCKED` if
the lease expired before worker execution.

For IME selection, test `getSelectedText` success/null/timeout/oversize and
malicious styled spans. Spans are discarded and only bounded plain ciphertext
is parsed. The alternative clipboard Activity remains manual and
ciphertext-only; after reading it, CipherBoard never overwrites clipboard with
plaintext. Embedded **Reply securely** resolves an opaque reply capability
against the current local contacts, clears the received surface, switches to
Encrypt, and selects that contact without starting an Activity or exposing its
ID in an Intent.

### 6.4 Protected viewer lifecycle

Test `FLAG_SECURE`, `excludeFromRecents`, no history state, no notification,
non-selectable text, no copy/share/Assistant/content-capture/autofill, immediate
hide, configured timeout, home/recent/back, task switch, screen off/on, lock,
rotation, multi-window attempt, process death, and reply. Screenshot/screen
record output must be blocked/blank according to the OS and the recent-app
thumbnail must not contain the sentinel. A `UiAutomation` accessibility dump
must not expose protected plaintext; non-secret controls retain localized
labels.

For the embedded surface, assert that plaintext is not acknowledged merely by
decoding or attaching it. Before the first draw, recheck active Decrypt mode and
an unexpired Vault; a denied draw must produce no pixels and no display
acknowledgement. The first allowed completed draw marks the display lease once
and only then starts the viewer timeout. A render timeout or stale callback
before acknowledgement wipes the drawing buffer and retains the encrypted
pending display; clear/hide/mode switch after acknowledgement closes the lease
and removes that record under no-history policy.

Recorded API 36 instrumentation covers a strict subset: process-text returned
`RESULT_CANCELED` with no data and left host text unchanged; the real viewer had
`FLAG_SECURE`, backgrounding closed the display lease and zeroized its tracked
byte and character buffers; and the explicit clipboard fallback retained the
original ciphertext clip. A separate `FLAG_SECURE` test capture produced a fully
black screencap; it is not secure-viewer-specific screenshot acceptance.
Secure-viewer screenshot output, recents, Accessibility, Assistant, screen lock
and the full IME selected-text path remain untested.

### 6.5 Localization and layout

Run screenshot/layout assertions for `en` and `ru`, light/dark, portrait/
landscape, font scales 1.0/1.3/2.0, display scaling, and pseudo-RTL. Verify all
product strings are resources, Russian has no accidental English fragments,
plurals/number grouping are correct, touch targets and content descriptions are
present for non-secret actions, no text overlaps/clips, and secret content is
deliberately excluded from TalkBack/accessibility export.

The v0.4 matrix also covers the Message format settings screen and compact,
Russian-word, and English-word estimates in both locales. Long word output must
wrap without overlapping controls. UI copy must call the word form camouflage
or presentation, never natural language, steganography, or extra encryption,
and must explain that both peers need version 0.4+ for word messages.

The v0.3 embedded panel has a release-specific responsive matrix. At minimum,
capture Encrypt and Decrypt states at a phone portrait viewport, phone
landscape, and font scale 2.0 in both English and Russian. Verify the two mode
labels, clear/close controls, ciphertext summary, **Paste and decrypt** or
**Вставить и расшифровать**, status text, scrollable plaintext, and **Reply
securely / Ответить защищённо** do not overlap or leave the IME viewport. In
Decrypt mode verify the ordinary keys are hidden; in Encrypt mode verify they
return. Long plaintext must scroll without resizing the command controls. This
visual matrix is a release QA requirement, not established by the drawing-only
Robolectric test.

Recorded manual API 36 smoke evidence includes Home and the v0.3 embedded panel.
The installed debug APK showed non-overlapping locked Encrypt and idle Decrypt
controls in English and Russian landscape at `font_scale=2.0`; the panel stayed
below the status bar and ordinary keys were absent in Decrypt. The earlier
locale-change receiver fix also remained stable. This evidence does not cover a
ready paired contact, rendered long plaintext, remaining screens, themes,
pseudo-RTL, accessibility or physical GrapheneOS input.

## 7. Storage, Keystore, and Lifecycle Tests

- Verify the Keystore alias is AES-256-GCM, non-exportable, user-authenticated,
  and reports the expected StrongBox or TEE level. Software/unknown fails closed
  under release policy and is labelled honestly.
- Exercise immediate/30-second/1-minute/5-minute leases with monotonic elapsed
  time, manual lock, app background, screen lock, reboot, first unlock, and
  process death. Default is one minute.
- Keep the device locked after reboot: the direct-boot-disabled IME/secure
  components do not open CE preferences or vault files. After first unlock,
  ordinary keyboard input works while every vault operation remains locked
  until explicit authentication.
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
Safety Number/short-code comparison, explicit verified/unverified decisions,
rename, fingerprint display/export, reverify, delete, session destroy, re-pair,
expired/cancelled offer, duplicate import, duplicate response, wrong pairing
ID, bad signatures, capability downgrade, identity change, and concurrent
offers. Rotate, background, lock the vault and kill the process at every screen;
the exact pending operation must either resume or become explicitly
cancellable/expired, with no inaccessible `ACTIVE` record left behind.

QR images and payloads must not appear in screenshots after leaving, recent
previews, logs, cache, media store, or analytics. Owner/contact local names are
absent from decoded protocol fixtures. No system Contacts permission or API is
used. There is no UI/intent for remote pairing in v1.

## 9. Leakage and Logging Tests

Inject a fresh high-entropy sentinel through the Private panel and decrypt viewer, then:

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
Private panel/viewer memory and pixels allowed by the design. Absolute JVM/
GPU RAM erasure is not asserted.

## 10. Static Analysis and Dependency Gates

Required commands, adapted to PowerShell/Gradle wrapper names on Windows:

```text
./gradlew lint
./gradlew test
./gradlew connectedCheck
./gradlew ktlintCheck          # or the pinned equivalent
./gradlew detekt               # or the pinned equivalent
cargo fmt --all --manifest-path crypto-core/native/Cargo.toml -- --check
cargo clippy --locked --all-targets --manifest-path crypto-core/native/Cargo.toml -- -D warnings
cargo test --locked --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock
(cd crypto-core/native && cargo +nightly fuzz run transport_parser \
  fuzz/corpus/transport_parser -- -max_total_time=60 -max_len=393216 -timeout=5)
```

Release additionally requires:

- strict `app/gradle.lockfile` and committed Rust `Cargo.lock` review. Refresh
  packageable Gradle locks only for an intentional dependency change with
  `./gradlew :app:resolveApplicationDependencyLocks --write-locks --no-configuration-cache`;
- SBOM generation for Gradle, Rust and packaged native components;
- OSV/cargo audit review with no untriaged applicable vulnerability. The clean
  pre-public local signed candidate passed with the pinned official OSV-Scanner
  v2.4.0, fresh offline Maven and crates.io databases, all 255 SBOM packages,
  and zero findings; repeat it for the final public release tag and archive that
  run's `VULNERABILITY_SCAN.json`;
- ktlint/detekt/Android lint with no release error;
- secret scan of tracked and distribution files;
- license compatibility/notices verification;
- source/dependency scan for network clients, localhost, Firebase, Play
  services, analytics, crash, ads, WebView, reflection/dynamic loaders;
- manifest review that treats both `INTERNET` and
  `REQUEST_INSTALL_PACKAGES` as forbidden, plus exported components, intent filters,
  providers, PendingIntent mutability, deep links, backup/data extraction,
  cleartext policy, and `usesCleartextTraffic`;
- path traversal/ZIP import/QR and styled-span parser tests;
- native ABI and hardening inspection (arm64-v8a release, x86_64 test;
  PIE/NX/RELRO/stack protection as toolchain applicable, stripped symbols,
  unwind contained by the JNI `catch_unwind` boundary, no unexpected `.so`);
- release Rust flag scan proving absence of `cfg(fuzzing)`.

## 11. APK and Release Verification

Run independent tools against the exact APK copied to `dist/`:

```text
cd dist
aapt dump permissions CipherBoard-<version>-release.apk
apkanalyzer manifest permissions CipherBoard-<version>-release.apk
apksigner verify --verbose --print-certs CipherBoard-<version>-release.apk
sha256sum CipherBoard-<version>-release.apk
sha256sum --check RELEASE_ARTIFACTS.sha256
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
  key, valid v2/v3 signing as supported, signer matches the reviewed public
  `SIGNING_CERTIFICATE_SHA256` pin, correct package/product name;
- only intended `arm64-v8a` release native libraries (and separately x86_64 in
  test artifacts); and
- SHA-256, signing certificate fingerprint, permissions, versions, ABI and git
  revision in `BUILD_INFO.txt` match independent tool output;
- `VULNERABILITY_SCAN.json` records the approved scanner/database/SBOM hashes,
  255 packages and zero findings; and
- every staged file matches `RELEASE_ARTIFACTS.sha256` after publication.

Any INTERNET occurrence, debug certificate, signature failure, plaintext test
key, or sensitive unvalidated exported component blocks release.

## 12. Residual Device Validation

The following cannot be signed off by Robolectric, JVM mocks, static analysis,
or the existing AOSP emulator. Evidence must identify OS build, device,
APK SHA-256, and test date without recording device identifiers or secrets.
These checks remain prerequisites before high-risk reliance and materially
increase assurance, but missing physical evidence is not itself a demonstrated
critical code vulnerability.

| Gate | Required physical evidence |
| --- | --- |
| D01 Two-party flow | Two devices perform reciprocal live-camera QR, compare values, send both ways, reorder and replay |
| D02 GrapheneOS/no Google | Current supported GrapheneOS on Pixel, no Sandboxed Google Play, full first-run/IME/process-text flow |
| D03 Network off | GrapheneOS Network permission disabled; app continues all flows; manifest independently lacks INTERNET |
| D04 StrongBox | Physical Pixel reports StrongBox for wrapping key and completes auth, restart, pair/send/decrypt |
| D05 TEE fallback | Physical/configuration with StrongBox unavailable reports TEE (not software) and completes the same flow |
| D06 Authentication | Real strong biometric and device credential success/cancel/lockout; lease timeouts and manual lock |
| D07 Invalidation | Controlled credential/key invalidation produces unrecoverable-vault state and re-pair recovery, no silent key creation |
| D08 Direct boot | Reboot without first unlock; direct-boot-disabled secure components do not access CE state; after unlock ordinary IME works and vault remains locked until authentication |
| D09 Window protection | Hardware/system screenshot, screen recording, recents, screen-off and lock tests show no plaintext capture |
| D10 Accessibility | Test Accessibility service/UiAutomation cannot extract protected plaintext; warning explains malicious services remain out of scope |
| D11 Host interoperability | AOSP SMS draft and real messenger single/multiline hosts receive exact compact/Russian/English ciphertext; copy/decrypt auto-detects all three; 0.4 accepts legacy SMS-profile `CB1`; selection decrypt leaves source unchanged; exact-live-connection field switches wipe/close; a physical-key sentinel demonstrates the documented bypass limitation |
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
| 5 Secure keyboard | embedded-panel/local-draft recording-connection suite, ordinary regression, exact-live-connection scope, password/hardware warnings, `READY`/`COMMIT_UNCERTAIN` ciphertext-only publication |
| 6 Decryption | both entry points, viewer lifecycle, replay/reorder, no result/clipboard/plaintext leakage |
| 7 UX/localization | en/ru, themes, font/orientation/RTL/accessibility and understandable error-state review |
| 8 Hardening | full fuzz/static/dependency/native/log/manifest/security review; all findings resolved or release-blocked |
| 9 Release | signed APK/APK tool agreement, SBOM/notices/build info, automated acceptance and install/update smoke; D01-D14 remain high-risk-use prerequisites |

## 14. Release Evidence Package

Archive without secrets: command versions, test XML summaries, fuzz corpus
hashes and duration, lint/static reports, merged manifest, aapt/apkanalyzer
permission output, apksigner certificate output and public signer pin, SBOM,
`VULNERABILITY_SCAN.json`, `RELEASE_ARTIFACTS.sha256`, dependency locks/audit,
device-validation checklist, APK SHA-256, git/upstream/vodozemac revisions, and
resolved `SECURITY_REVIEW.md`. Never archive plaintext fixtures, private
identities, release keystore/password, full QR captures, or local contact data.

A release report distinguishes **passed**, **failed**, **blocked (no device)**,
and **not run**. Missing physical GrapheneOS, StrongBox, TEE, biometric,
invalidation, direct-boot, screenshot, or two-camera evidence remains explicitly
unverified residual validation and a prerequisite before high-risk use; it is
not converted into a pass by unit mocks or mislabeled as a known critical code
defect.
