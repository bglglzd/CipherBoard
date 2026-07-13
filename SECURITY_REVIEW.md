# CipherBoard Security Review Status

**Review date:** 2026-07-13

**Reviewed tree:** current 2026-07-13 worktree. A clean pre-public local signed
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

## Implemented Controls

| Area | Current source control | Evidence still required |
| --- | --- | --- |
| Crypto | vodozemac Olm v2; signed offer/response; exact Rust versions | final protocol review, golden vectors, pairing/JNI fuzzing |
| Envelope | bounded `CB1` Base64url/canonical-CBOR map; duplicate/core-field/trailing-byte checks; order-independent parts; real ASan/libFuzzer campaign | longer scheduled and Android/device tests |
| Replay | 4096 IDs in serialized session plus per-contact 8192-marker SQLite bound committed with inbound state | inbound SIGKILL/reopen test passes; wider long-run/device restart matrix remains |
| Storage | AES-256-GCM records with type/key/schema/revision AAD; random nonces; no-backup CE location | stolen-DB, WAL/SHM, corruption and backup/transfer device tests |
| Keystore | non-exportable AES wrapping key; StrongBox-first; only reported TEE accepted as fallback; software/unknown rejected; user authentication | real StrongBox/TEE/invalidation/reboot tests |
| Send atomicity | advanced ratchet plus contact-bound exact pending ciphertext commit before a one-shot host/editor-scoped IME handoff; exact retry without re-encrypt | real SIGKILL before commit and after commit/before handoff pass; in-transaction and real host-ack window remain |
| Receive atomicity | replay, advanced ratchet and encrypted pending display commit together; exact-ciphertext digest recovery; pre-render abandon retains record | real post-commit SIGKILL and close/reopen pass; in-transaction failpoints remain |
| Composer | separate `FLAG_SECURE` activity, no saved view state/autofill/copy/cut/paste/share, no-learning/clipboard-history gates, background clearing | hostile `InputConnection`, clipboard/learning/log/storage sentinel suite |
| Decrypt/viewer | hostile selected-text bounds, read-only process-text result, vault auth, drawing-only inaccessible text, `FLAG_SECURE`, recents/background/timeout cleanup, reply by contact ID | process-text/FLAG_SECURE/background wipe/zeroization and clipboard fallback pass on AOSP; a separate `FLAG_SECURE` test screencap is black, while secure-viewer screenshot/recents/Assistant/Accessibility/screen-lock evidence remains |
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
host `InputConnection.commitText()`, or exercise a complete IME/composer/live-
camera pairing flow. Android cannot know whether a host accepted `commitText()`
immediately before process death; recovery may reinsert the exact ciphertext
but must never re-encrypt from stale state, and the receiver rejects a duplicate
as replay. These are explicit remaining coverage gaps, not claims of a test pass.

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
- Selected-text entry paths intentionally use different UI bounds; the larger
  viewer grammar and smaller IME selection cap need device UX coverage.
- JVM/Android UI objects, public routing/fingerprint summaries and local names
  cannot be guaranteed to zeroize before garbage collection.
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

## Required Work Before High-risk Use

1. Repeat and archive the seven passing AOSP instrumentation tests on the exact
   release commit; add individual SQLite-statement failpoints, the real
   `InputConnection.commitText()` acknowledgement window, and complete
   IME/composer/pairing-camera E2E coverage.
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
