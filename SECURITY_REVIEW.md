# CipherBoard Security Review Status

**Review date:** 2026-07-14

**Reviewed tree:** current 2026-07-14 worktree. A clean pre-public local signed
candidate was verified separately, but its local evidence bundle is not tracked
or published and must not be transferred to the rewritten public history.

**Assurance:** internal source/document review, not an independent audit and not
a production release approval

Evidence below applies only to the named source, tests, or artifact. The prior
local candidate has signature and merged-manifest evidence, but it does not
establish those properties for a later public-source commit, and it provides no
physical-device or GrapheneOS evidence.

## Evidence Observed

- `vodozemac 0.10.0` is exact-versioned with default features disabled and Olm
  `SessionConfig::version_2()` enforced. Rust Cargo lockfiles are checked in.
- The latest native test run reported 27 passing tests. The suite covers
  Alice/Bob pairing and matching comparison values, bidirectional traffic,
  1000 messages, bounded reordering, replay after state restore, tamper,
  truncation, Unicode, multipart bounds, state corruption, transactional API
  boundaries, and canonical-CBOR regressions. Rust format and Clippy checks
  were also reported passing in the same work session.
- The complete current Gradle unit gate passes for `:app:testDebugUnitTest`,
  `:crypto-core:testDebugUnitTest`, `:pairing:testDebugUnitTest`, and
  `:secure-storage:testDebugUnitTest`. Module release lint gates also pass. Two
  inherited HeliBoard regressions are explicitly `@Ignore`d with issue-specific
  reasons; the full current gate does not rely on the older `runTests` build-
  type bypass.
- A pinned `cargo-fuzz 0.13.2`/`libfuzzer-sys 0.4.13` ASan campaign exercised
  the production `CB1`/canonical-CBOR envelope parser for 601,574 inputs in 31
  seconds with zero crashes or timeouts. The tracked harness has three bounded
  modes and three seed files. This is useful parser evidence, not a substitute
  for longer scheduled runs or pairing/JNI fuzz targets.
- `:app:connectedDebugAndroidTest --no-configuration-cache` passed 7/7 tests
  with zero failures/skips on the API 36 x86_64 `CipherBoard_API_36_AOSP`
  no-Play emulator. The tests verify read-only process-text return behavior,
  protected-viewer flags/background wiping, ciphertext-only clipboard fallback,
  two close/reopen storage transactions, and three actual remote-process
  `Process.killProcess`/SIGKILL boundaries. The fault fixture exists only in the
  debug manifest/source set and is excluded from release.
- The current debug APK also installed and launched its Home activity on that
  emulator. English and per-app `ru-RU` Home hierarchies had bounded,
  non-overlapping controls; Russian Home also fit in landscape at
  `font_scale=1.3`. A `FLAG_SECURE` test capture was fully black, but this is not
  secure-viewer screenshot acceptance. An inherited `SystemBroadcastReceiver`
  locale-change self-termination loop found before IME selection was fixed; the
  rebuilt process remained alive for the recorded three-second observation and
  exposed the Russian hierarchy.
- Source review confirms `allowBackup=false`, all-domain backup/device-transfer
  exclusions, cleartext denial and no `INTERNET` or `ACCESS_NETWORK_STATE`
  declaration. The CameraX video/media dependency path that introduced the
  latter permission is excluded.
- Packageable `:app` dependency graphs use strict locking in the checked-in
  `app/gradle.lockfile`. Release SBOM generation consumes the resolved Gradle
  graph plus locked Rust graphs; the generated artifact still needs manual
  license review.
- The release preflight verified an official OSV-Scanner v2.4.0 binary against
  its pinned SHA-256 allowlist, required fresh local Maven and crates.io
  vulnerability databases, and scanned all 255 CycloneDX SBOM packages fully
  offline. It exited successfully with zero findings and produced
  `VULNERABILITY_SCAN.json`. The pre-public local signed candidate repeated this
  gate; the final public tag must repeat it and publish its own report.
- GPLv3/Apache/BlueOak/CC texts, consolidated BSD notices, upstream provenance
  and the license inventory are generated as offline APK assets, required
  nonempty by a unit test, and displayed by a non-exported local license
  activity. Release staging also creates an exact-commit source archive; both
  outputs still require inspection on the final artifact.
- Source search found no production HTTP client, Firebase, Google Play Services,
  analytics, crash-reporting, advertising, WebView, or dynamic-code-loader use.
  An inherited JVM test uses `HttpURLConnection`; it is not packaged production
  code.
- New Vaults on API 23--29 fail closed to a biometric authentication-per-use
  Keystore key with validity `-1`. The legacy API cannot express the requested
  biometric-or-device-credential policy without a time-based authorization
  window, so device-credential fallback is available only on API 30 and newer.
  Existing pre-release credential-window envelopes remain readable but no new
  positive-duration legacy key is generated.
- The v0.2 source replaces shield-to-activity navigation with an embedded
  Private mode panel. Software-key and IME edit paths target a bounded local
  draft, the active host is scoped by exact `InputBinding.connectionToken`, and
  personalized learning/clipboard-history paths are disabled. Detailed
  inherited InputLogic diagnostics are unconditionally suppressed for the
  secure editor, including chosen words, n-gram context and code points; a
  policy regression test covers this gate. Visual emulator
  inspection confirmed that the panel remains inside the IME bounds and a
  `FLAG_SECURE` capture was black; full host-field/leakage instrumentation on the
  exact release commit remains required.
- The v0.3 source adds an embedded copied-ciphertext Decrypt mode. One explicit
  action reads exactly one bounded clipboard text item, the clipboard remains
  ciphertext, ordinary keys are hidden, and plaintext is owned by a
  drawing-only surface excluded from selection, Accessibility text, autofill,
  content capture and saved state. Targeted Robolectric tests for the clipboard
  reader and surface pass; a real IME/Telegram/GrapheneOS flow remains required.
- Pending-display acknowledgement now occurs on the first allowed completed
  plaintext draw, not when bytes are decoded or attached to a view. The
  pre-draw Vault check and one-shot callback are unit-tested. A three-second
  render timeout clears without marking the lease, retaining the encrypted
  recovery record for an exact retry.
- Worker results posted toward the embedded panel have explicit ownership.
  Generation cancellation drains queued values and closes late parse/decrypt
  successes, including their plaintext, instead of silently removing a handler
  callback. Focused concurrency tests cover post-versus-close races.
- Vault authentication for the embedded flow uses a process-local random token
  accepted once by the non-exported activity and completed once back to the
  controller. The Activity Intent carries no ciphertext or plaintext. Targeted
  tests cover activation, duplicate completion and cancellation, and the
  hostless backend fails `VAULT_LOCKED` rather than opening authentication UI.
- The Activity viewer cancels parse/decrypt work on pause, stop, user-leave and
  UI-hidden transitions, except while its own legacy system-credential result
  is pending. Its first-draw gate reapplies Vault expiry immediately before
  rendering. The legacy unlock host is non-exported and no longer uses
  `noHistory`, which would destroy it before an Android 6-10 credential result.
- Pending outbound records now have versioned `READY` and
  `COMMIT_UNCERTAIN` states. The latter is durably set before host
  `commitText()` and is excluded from automatic retry. Codec, store and bridge
  unit tests exist. Legacy schema-1 pending sends fail safe to
  `COMMIT_UNCERTAIN`, since their prior handoff state is unknowable. The real
  Binder acknowledgement/process-death window remains an explicit platform
  test gap.

## Implemented Controls

| Area | Current source control | Evidence still required |
| --- | --- | --- |
| Crypto | vodozemac Olm v2; signed offer/response; exact Rust versions | final protocol review, golden vectors, pairing/JNI fuzzing |
| Envelope | bounded `CB1` Base64url/canonical-CBOR map; duplicate/core-field/trailing-byte checks; order-independent parts; real ASan/libFuzzer campaign | longer scheduled and Android/device tests |
| Replay | 4096 IDs in serialized session plus per-contact 8192-marker SQLite bound committed with inbound state | inbound SIGKILL/reopen test passes; wider long-run/device restart matrix remains |
| Storage | AES-256-GCM records with type/key/schema/revision AAD; random nonces; no-backup CE location | stolen-DB, WAL/SHM, corruption and backup/transfer device tests |
| Keystore | non-exportable AES wrapping key; StrongBox-first; only reported TEE accepted as fallback; software/unknown rejected; user authentication | real StrongBox/TEE/invalidation/reboot tests |
| Send atomicity | advanced ratchet plus contact-bound exact pending ciphertext commit; `READY` changes durably to `COMMIT_UNCERTAIN` before one exact-token-scoped host commit; uncertain delivery cannot auto-retry | existing SIGKILL commit-boundary tests and new codec/store/bridge unit coverage; individual SQLite statements and real host-ack window remain |
| Receive atomicity | replay, advanced ratchet and encrypted pending display commit together; exact-ciphertext digest recovery; pre-first-draw abandon retains record; first allowed draw acknowledges the lease | real post-commit SIGKILL and close/reopen plus targeted first-draw tests pass; in-transaction and post-draw/pre-close kill failpoints remain |
| Private panel | shield toggles an embedded `FLAG_SECURE` IME panel; bounded Encrypt draft; software keys/edit actions route locally; Decrypt hides keys; no saved state/plaintext copy/share/learning/clipboard history; exact connection-token scope and lifecycle clearing | locked Encrypt and idle Decrypt states fit API 36 landscape at font scale 2.0 in English/Russian; paired-contact/long-text matrix, hostile-host, hardware-keyboard and physical GrapheneOS evidence remain |
| Decrypt/viewer | explicit bounded ciphertext clipboard read; clipboard unchanged; owned result handoff; one-shot unlock token; drawing-only inaccessible embedded/activity text; render-time Vault gate; background cancellation; local opaque reply capability | targeted v0.3 race/surface tests and 7/7 API 36 process-text/FLAG_SECURE/background-wipe/clipboard instrumentation pass; embedded paired-contact E2E, screenshot/recents/Assistant/Accessibility/screen-lock evidence remains |
| Pairing/contact | signed native offer/response; encrypted one-shot state; bounded orphan cleanup; explicit comparison; changed identity blocks use until verification | live two-device, camera permission, lifecycle, process-kill and hostile-QR instrumentation |
| QR | local ZXing codec and lifecycle-bound CameraX scanner with bounded ASCII payloads; Camera requested only by the Scan actions | real permission grant/deny/revoke and two-device camera evidence |
| Manifest/signing | source backup/cleartext controls, forbidden-permission tests and public release-certificate SHA-256 pin; a pre-public local signed candidate passed scripted APK/signature policy | repeat `aapt`/`apkanalyzer`/`apksigner` verification and publish its evidence for the final public tag |

## Verified Android Instrumentation Scope

The previous broad full-app/process-kill evidence blocker is closed for the
seven demonstrated API 36 AOSP tests. Specifically:

- process-text returns `RESULT_CANCELED` with no result data and leaves host text
  unchanged; the viewer sets `FLAG_SECURE`, wipes byte/character plaintext on
  background, and closes its display lease;
- ciphertext clipboard fallback occurs only after the explicit action and the
  original ciphertext clip remains unchanged;
- outbound pending ciphertext and inbound replay/pending-display state remain
  atomic across ordinary store close/reopen; and
- three debug-only remote `:fault` process cases use actual SIGKILL before
  outbound commit, after outbound commit before handoff, and after inbound
  commit, then assert revision, exact pending ciphertext, replay marker and
  pending display after reopening storage.

This evidence does not inject a crash between individual SQLite statements
inside one transaction, kill immediately around acknowledgement from a real
host `InputConnection.commitText()`, or exercise a complete IME/private-panel/live-
camera pairing flow. Android cannot know whether a host accepted `commitText()`
immediately before process death. The v0.2 handoff marks the operation
`COMMIT_UNCERTAIN` before that call and does not automatically reinsert it; the
user must inspect the transport. The receiver rejects a duplicate as replay.
These are explicit remaining coverage gaps, not claims of a test pass.

The v0.3 additions have JVM/Robolectric race and surface evidence plus the
existing API 36 instrumentation suite. Targeted runs pass for the embedded
surface/clipboard, one-shot unlock, owned-result handoff, reply transition,
render-time Vault gate, background cancellation and secure-IME lifecycle. The
7/7 device suite confirms process-text plaintext remains inside a protected
viewer, its owned buffers wipe on background, and clipboard ciphertext remains
unchanged. Manual API 36 inspection confirms locked Encrypt and idle Decrypt
controls fit the IME in English and Russian landscape at font scale 2.0, with
ordinary keys absent in Decrypt. This does not establish a paired-contact
embedded decrypt, BiometricPrompt behavior, a live Telegram integration, or
physical GrapheneOS behavior.

## Residual Validation Before High-risk Use

The following are assurance prerequisites and residual validation, not known
critical source-code defects:

- independent applied-cryptography and Android security review of the exact
  protocol bytes, state transitions, IME/JNI/storage boundaries and final build;
- physical GrapheneOS operation without Google Play, live two-camera QR pairing,
  just-in-time permission grant/deny/revoke, and Network permission denial;
- real StrongBox and TEE-only generation, authentication, reboot, timeout and
  invalidation behavior; and
- screenshot/recents/Accessibility/Assistant/screen-lock validation plus
  independent hash, signature, permission, SBOM, vulnerability, source/license
  bundle and installation checks for the exact clean final artifact.

Lack of independent audit or physical-device evidence limits assurance and must
be disclosed before high-risk use. It should not be mislabeled as a critical
code vulnerability when no such defect has been demonstrated.

## Documented Residual Risks and Follow-up

- SQLite lookup/replay hashes, record kinds, revisions and timestamps expose
  bounded count/timing metadata and permit denial-of-service tampering, while
  secret values and ratchet state remain AEAD-encrypted.
- Embedded clipboard, selected-text and process-text entry paths share bounded
  plaintext-free parsing but still need hostile transport and device UX
  coverage across their different Android framework boundaries.
- The display lease's acknowledged flag is process-local until the surface
  closes and deletes the encrypted pending record. Process death after first
  draw but before close can therefore leave that record recoverable for the
  bounded crash-recovery window; v1 is not a strict exactly-once viewer.
- JVM/Android UI objects, public routing/fingerprint summaries and local names
  cannot be guaranteed to zeroize before garbage collection.
- Android may route a physical keyboard directly to the focused host view,
  bypassing the IME's local Private draft. Private input is supported only with
  CipherBoard's on-screen keys; a physical-device warning/host sentinel remains
  required.
- The 601,574-input ASan/libFuzzer run covers the envelope parser only; pairing,
  inner and JNI codecs need additional targets and longer scheduled campaigns.
- Restricted temporary password files avoid command-line disclosure, but
  PowerShell/JVM memory cannot be guaranteed to zeroize; offline signing remains
  preferable for a high-assurance release process.

Previously reported source findings for unbounded offer lifetime, secure-mode
paste, release panic handling, and absent invalidated-vault recovery have been
closed in the current tree. Import bounds signed expiry against receiver time;
secure editor/IME actions block paste and clipboard-history paths; Rust release
profiles unwind into the JNI `catch_unwind` boundary; and destructive vault
reset is offered only after observed key invalidation with explicit confirmation.
The earlier shield-to-activity overlap is also closed by the embedded Private
panel, and the external acknowledgement ambiguity is represented durably as
`COMMIT_UNCERTAIN` rather than an automatically retryable send.
The absence of text actions in transports such as Telegram is addressed by the
v0.3 shield-panel Decrypt mode; plaintext remains inside CipherBoard, while only
copied ciphertext crosses the clipboard boundary.

## APK Policy Review

`scripts/verify-apk` is designed to fail on forbidden permissions, backup or
cleartext enablement, release debug/test flags, unknown exported shapes,
network deep links, Firebase/GMS/advertising/analytics/crash/WebView/dynamic
loader markers, invalid/non-v2/debug/mismatched-certificate signing and ZIP
alignment failures. Release staging also hashes every published output.

This policy scanner ran successfully against the pre-public local signed
candidate. Its local evidence is not tracked or published and must not be used
to verify the rewritten public history. It must run again for the final public
tag before publication. Even a passing result cannot prove semantic caller
validation, absence of native defects, absence of obfuscated behavior, or
plaintext non-disclosure. It is a release blocker plus manual review, not an
audit.

CipherBoard intentionally provides no in-app updater and requests neither
`INTERNET` nor `REQUEST_INSTALL_PACKAGES`. Stable update discovery is delegated
to an external installer such as Obtainium using GitHub Releases; that installer
is a separate networked trust boundary.

## Required Work Before High-risk Use

1. Repeat and archive the seven passing AOSP instrumentation tests on the exact
   release commit; add individual SQLite-statement failpoints, the real
   `InputConnection.commitText()` acknowledgement window, and complete
   IME/private-panel/pairing-camera E2E coverage.
2. Run the full Gradle/Rust/static/fuzz/crash/leakage suite and repeat the pinned
   offline OSV scan on a clean commit.
3. Exercise physical GrapheneOS, live camera pairing, StrongBox/TEE,
   authentication/invalidation, direct boot and protected windows as residual
   platform validation.
4. Repeat build/sign/verification on the final public release tag and
   independently recompute its permissions, hash, certificate and complete
   artifact manifest; do not reuse the pre-public local candidate evidence.
5. Obtain independent Android security and applied-cryptography review of the
   exact protocol/build and remediate any findings before high-risk reliance.

Сборка реализует проверенные криптографические примитивы и прошла автоматические
тесты, но весь продукт не следует считать независимо аудированным до проверки
внешним специалистом по прикладной криптографии и Android security.
