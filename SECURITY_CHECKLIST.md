# CipherBoard Security Checklist

**Snapshot date:** 2026-07-14
**Public release branch:** `main`
**Upstream baseline:** HeliBoard `v4.0`, commit
`bd48798b99cccc99704eebf2a9259c02dbd684d5`
**Prior signed candidate:** pre-public local build; its evidence bundle is
untracked and unpublished, so the final public tag must generate its own
`BUILD_INFO.txt` and release assets

This is a traceable implementation and release checklist. It is not a security
certificate. Update an item's state only with evidence tied to the current
commit and, where applicable, the exact APK.

The complete app/library debug unit gates and module release lint gates pass on
the current worktree. Native Rust reports 27 passing tests plus format/Clippy
success. A bounded ASan/libFuzzer envelope campaign completed 601,574 inputs
without a crash or timeout. Strict packageable dependency locking is checked in
at `app/gradle.lockfile`. An offline OSV preflight scanned all 255 SBOM packages
with the pinned official v2.4.0 scanner and fresh Maven/crates.io databases,
returning zero findings. A clean pre-public local signed-candidate pipeline then
repeated these gates, signed with the pinned non-debug certificate, passed the
scripted APK/signature/permission policy, and emitted its evidence package.
That evidence is specific to that commit and must be regenerated after the
public-source changes; it is not connected physical-device or GrapheneOS
evidence. Targeted full-app Android instrumentation passes 7/7 on an API 36
x86_64 AOSP no-Play emulator, including three actual debug-only remote-process
SIGKILL boundaries; its narrower gaps are recorded below.

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

Physical GrapheneOS/StrongBox/camera checks and independent review remain
residual validation prerequisites before high-risk reliance. Their pending
status limits assurance but is not, by itself, a demonstrated critical code
defect. The previous broad full-app/process-kill evidence blocker is closed only
for the seven demonstrated AOSP tests; in-transaction failpoints, the real
`commitText()` acknowledgement window and complete IME/private-panel/camera E2E are
still unverified.

## 1. Provenance, Governance, and Documentation

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| GOV-01 | Source is based on official HeliBoard stable tag `v4.0` at the recorded commit | 5 | Verified | `git tag --points-at HEAD` and `git rev-parse HEAD` were checked before product changes |
| GOV-02 | Public release branch is `main`; artifacts identify an immutable source commit | 4 | Implemented | Branch publication/protection must be checked on the hosted repository; generated `BUILD_INFO.txt` records the source commit |
| GOV-03 | Upstream tag/commit and modification relationship are recorded | 5 | Implemented | `UPSTREAM.md`; review before release |
| GOV-04 | GPLv3 license, source obligations, and upstream notices are preserved | 5 | Implemented | Complete license texts/notices are retained, packaged for offline viewing, and included with the exact-commit source archive; final artifact review pending |
| GOV-05 | Third-party versions, licenses, and notices are complete | 5, 30 | Implemented | GPL/Apache/BlueOak/CC texts, consolidated BSD notices, inventory/notices and nonempty offline-asset unit test exist; final resolved-graph/manual review pending |
| GOV-06 | Threat model accurately states scope and residual risk | 3 | Implemented | `THREAT_MODEL.md`; independent security review pending |
| GOV-07 | Architecture, crypto protocol, build, release, and test documents match code | 6, 30 | Implemented | 2026-07-14 embedded-Private-mode documentation audit; repeat at release candidate |
| GOV-08 | UI/README contain no absolute-security or independent-audit claims | 3, 33 | Implemented | Security UI and docs state limitations/no independent audit; final resource scan pending |
| GOV-09 | No passwords, private keys, signing files, or credentials are tracked | 4, 29 | Pending | Secret scan plus Git history review |

## 2. Runtime Network and Dependency Boundary

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| NET-01 | Final merged manifest has no `android.permission.INTERNET` | 2, 19, 28 | Verified | Source and the pre-public local signed candidate passed the independent-tool APK permission policy; repeat for the final public tag, with INTERNET remaining a hard blocker |
| NET-02 | No `ACCESS_NETWORK_STATE` or other network permission | 2, 19 | Verified | Source and pre-public local signed-candidate permission dumps contain no network permission; repeat for the final public tag |
| NET-03 | Runtime performs no network or localhost request | 2 | Implemented | Production-source scan found no client/call; denied-Network device traffic test pending |
| NET-04 | No Firebase, FCM, Play Services, analytics, crash-reporting, advertising, or remote-config SDK | 2, 20, 28 | Verified | Source, dependency and pre-public local signed-candidate APK policy scans passed; rerun against the final public artifact |
| NET-05 | No WebView, dynamic code loading, downloaded model/dictionary/configuration, or proprietary cloud QR API | 2, 19, 27 | Implemented | Source uses local ZXing/CameraX and packaged assets; the pre-public local candidate's APK marker scan passed, while physical runtime verification remains pending |
| NET-06 | App works on GrapheneOS without Sandboxed Google Play | 20, 31 | Pending | Physical-device acceptance evidence |
| NET-07 | GrapheneOS Network denial is documented as defense in depth | 20 | Implemented | `RELEASE.md`, `THREAT_MODEL.md`; installation walkthrough review pending |
| NET-08 | Update checks/install are external; CipherBoard has no in-app updater, `INTERNET`, or `REQUEST_INSTALL_PACKAGES` | 2, 20, 28 | Implemented | README/release notes document Obtainium as a separate trust boundary; final manifest and update-over-existing-install test pending |

## 3. Cryptographic Library and FFI

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| CRY-01 | Crypto ADR evaluates official `vodozemac`, security policy, audits, support, and Apache-2.0/GPLv3 compatibility | 7.2 | Implemented | `docs/adr/0001-crypto-library.md`; external review pending |
| CRY-02 | Exact crypto library version/commit is pinned and dependency-locked | 7.2, 27 | Implemented | Exact `0.10.0` and Cargo lockfiles; final SBOM/build info pending |
| CRY-03 | No custom Curve25519, Ed25519, AEAD, HKDF, ratchet, RNG, hash, signature, or PGP-like scheme | 7.1 | Implemented | Source delegates primitives/Olm to vodozemac, sha2, JCA/Keystore; independent crypto review pending |
| CRY-04 | v1 uses one-to-one Olm/Double Ratchet, not Megolm/group sessions | 7.2 | Implemented | `SessionConfig::version_2()` source/tests; no Megolm API use found |
| CRY-05 | FFI API is minimal, length checked, typed, and does not stringify keys/state | 7.2, 24 | Implemented | One byte-oriented JNI dispatch and bounded CBOR/error mapping; envelope parser has real ASan/libFuzzer evidence, JNI-specific target pending |
| CRY-06 | Secret Rust buffers use `zeroize` where ownership permits and do not leak through `Debug`/panic | 7.2, 24 | Implemented | `SecretBytes`/temporary state clearing, redacted errors, release unwind and JNI `catch_unwind`; independent review pending |
| CRY-07 | Sender authentication, integrity, forward secrecy, DH and symmetric ratchets are exercised end to end | 7.3, 25 | Implemented | Native Alice/Bob/1000-message tests; Android integrated evidence pending |
| CRY-08 | Skipped-key storage is bounded and used keys are not retained | 7.3 | Implemented | vodozemac limits, 4096 in-session seen IDs, and 8192 per-contact storage markers; exact boundary/device evidence pending |
| CRY-09 | Crypto/dependency security advisories are reviewed for the pinned versions | 7.2, 27 | Implemented | Prior `cargo audit` reported clean; rerun on release commit |

## 4. Identity and Pairing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| ID-01 | First run creates a local identity without registration or network identifier | 8 | Implemented | Local owner creation exists after vault unlock; onboarding/device test pending |
| ID-02 | Local owner/contact names are not cryptographic identity and are not shared without confirmation | 8, 9 | Implemented | Crypto QR schema contains no name/device identifier; integrated UI test pending |
| ID-03 | Clearing data/reinstalling creates a new identity and requires re-pairing | 8, 10 | Pending | Lifecycle instrumentation test |
| ID-04 | Identity replacement produces blocking `Key changed`/`Pairing required`, never silent acceptance | 8, 10 | Implemented | Storage/runtime detect the changed fingerprint and block use until explicit physical re-pairing and comparison confirmation; device test pending |
| PAIR-01 | Pairing offer has random ID/nonce, expiry, one-time key material, protocol version, and bounded capabilities | 9 | Implemented | Native signed CBO1 arrays/tests; provisional format differs from requested design |
| PAIR-02 | Pairing payload excludes phone/email/device/account/location/system-contact identifiers | 9 | Implemented | Actual array schema reviewed in `CRYPTO_PROTOCOL.md`; final fixture review pending |
| PAIR-03 | Pairing offer is single-use; replay, expiry, duplicate import, and deletion are enforced | 9, 25 | Implemented | Both-role ledger, explicit deletion, bounded cleanup and maximum-lifetime-plus-clock-tolerance import check are tested; real-storage process-kill test pending |
| PAIR-04 | Response cryptographically binds both identities and complete transcript | 9 | Implemented | Signed response plus encrypted offer-hash/nonce binder; final protocol review pending |
| PAIR-05 | Both devices derive identical numeric and emoji/word codes from one transcript hash | 9, 25 | Implemented | Native tests match the 80-digit Safety Number and eight-word code from one transcript; physical comparison pending |
| PAIR-06 | Contact becomes `Verified` only after explicit Safety Number comparison/confirmation | 9 | Implemented | Both activity roles call atomic contact creation only from explicit confirmation; two-device/UI instrumentation pending |
| PAIR-07 | QR scanning is offline, parser-bounded, and requests camera only after user action | 19 | Implemented | Local ZXing/CameraX path; permission launcher is reached only from Scan actions; physical grant/deny/revoke test pending |
| PAIR-08 | Remote pairing through a messenger is absent in v1 | 9 | Implemented | No exported pairing/import intent or remote-pair UI in current source |

## 5. Contacts and Session Lifecycle

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| CON-01 | Contacts store only required local fields and encrypted session/replay state | 10, 16 | Pending | Contact/session/seen-ID values are encrypted, but hashed lookup/replay indexes and timestamps remain plaintext metadata |
| CON-02 | Add, rename, fingerprint/Safety Number view, reverify, delete, reset, and re-pair flows work | 10 | Implemented | Source flows and process-local navigation token exist; repository/coordinator/navigation tests pass, Compose/device instrumentation pending |
| CON-03 | Deletion removes local session material as reliably as Android permits and explains flash-storage limits | 10, 16 | Implemented | Atomic contact/session/pending/replay deletion code/tests; device filesystem test pending |
| CON-04 | Public fingerprint export contains no private/contact/system metadata | 10 | Implemented | Confirmation-gated export and fixture test verify fingerprint-only `EXTRA_TEXT`; external target-app test pending |
| CON-05 | Damaged sessions fail closed with `Session error` and require explicit recovery | 7.3, 10 | Implemented | Strict state/AEAD errors and blocking status exist; recovery UI/device test pending |

## 6. Envelope, Unicode, and Multipart Parsing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| ENV-01 | Outer format is versioned `CB1:` with Base64url without padding and deterministic binary encoding | 12 | Implemented | Canonical-CBOR regressions exist; stable golden vectors pending |
| ENV-02 | Envelope exposes only required opaque routing/reassembly metadata; sensitive metadata is encrypted | 12 | Implemented | Actual nine-field schema reviewed; final metadata/privacy protocol decision pending |
| ENV-03 | Parser rejects invalid Base64, duplicate/unknown mandatory fields, trailing bytes, invalid versions, and inconsistent IDs | 12, 25 | Implemented | Native negative/canonical tests plus 601,574-input ASan/libFuzzer envelope campaign with no crash/timeout; longer scheduled runs pending |
| ENV-04 | Parser enforces input, field, nesting, allocation, part-count, and total-size limits | 12, 13 | Implemented | 32 fields, scalar-only extensions, 32 KiB token, 256 KiB payload, 128 parts; bounded production-parser fuzz harness included |
| ENV-05 | Multipart assembly is order independent, detects gaps/duplicates, and decrypts only when complete | 13 | Implemented | Native permutation/gap/duplicate tests; Android integration pending |
| ENV-06 | Universal and SMS compact modes use transport-safe ASCII and report size/part estimates | 13 | Implemented | SMS uses 48-byte chunks; native regressions assert each complete part is ASCII and at most 153 characters; carrier/device test pending |
| ENV-07 | Plaintext is not compressed by default | 13 | Implemented | Direct byte-to-inner-CBOR/Olm path; final source review pending |
| ENV-08 | UTF-8 round trip is byte-exact without normalization for required Unicode classes | 12, 25 | Implemented | Native Unicode and strict Android encode/decode paths; full class/UI matrix pending |
| ENV-09 | Arbitrary parser input cannot panic/crash or allocate without bound | 25 | Implemented | Property regressions and pinned cargo-fuzz corpus completed 601,574 ASan inputs in 31 seconds with no crash/timeout; longer/multi-platform evidence pending |

## 7. Ratchet Atomicity and Replay

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| RAT-01 | Send transaction atomically commits advanced state plus exact pending ciphertext before host commit | 17 | Implemented | Targeted API 36 PASS: remote-process SIGKILL before outbound commit and after commit/before handoff; revision and exact pending ciphertext are asserted after reopen; individual SQLite-statement crash points remain |
| RAT-02 | `READY` ciphertext is claimed once; the record becomes `COMMIT_UNCERTAIN` before host commit and uncertain delivery never auto-retries | 17 | Implemented | Versioned codec/store/bridge tests cover the durable transition and no-auto-retry policy; a kill immediately around real host `commitText()` acknowledgement remains untested |
| RAT-03 | Receive transaction commits advanced state plus encrypted pending display before showing plaintext | 17 | Implemented | Targeted API 36 PASS: post-inbound-commit remote SIGKILL/reopen asserts revision, replay marker and pending display; individual SQLite-statement failpoints remain |
| RAT-04 | Pending display is removed on close with no retained message key/plaintext history | 17, 18 | Implemented | Pre-render abandon retains encrypted recovery; render acknowledgement then close deletes it; lifecycle/process-death test pending |
| RAT-05 | Replay is rejected across process/device restart | 7.3, 17, 25 | Implemented | Serialized/native restore coverage plus actual post-inbound-commit SIGKILL/reopen preserves the SQLite replay marker; full device reboot/long-run matrix pending |
| RAT-06 | Out-of-order and skipped messages work within fixed bounds | 7.3, 25 | Implemented | Native shuffled/omitted sequence tests; Android integrated evidence pending |
| RAT-07 | Concurrent send attempts serialize safely per session | 25 | Implemented | Process-wide runtime lock and revision conflicts; concurrency stress/device test pending |
| RAT-08 | Crash points before/after save and before host transfer cannot reuse ratchet state | 17, 25 | Implemented | Three debug-only remote `:fault` tests use actual `Process.killProcess`/SIGKILL before outbound commit, after outbound commit/before handoff, and after inbound commit; no in-transaction statement or real host-ack-window injection yet |
| RAT-09 | Backup/restore and cloning of ratchet state are disabled; privileged same-device rollback remains documented residual risk | 16, 17 | Implemented | Source backup/extraction rules and threat model; APK/backup/device-transfer test pending |

## 8. Keystore, Vault, and Encrypted Storage

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| STO-01 | Non-exportable wrapping key is generated in Android Keystore | 16 | Implemented | AES Keystore generation source; real KeyInfo evidence pending |
| STO-02 | StrongBox is attempted first; TEE fallback is nonfatal and actual security level is shown | 16, 25 | Implemented | StrongBox-first, level inspection, TEE-only acceptance and software/unknown rejection exist; physical StrongBox/TEE evidence pending |
| STO-03 | Wrapping key requires `BIOMETRIC_STRONG` or device credential | 16 | Implemented | KeyGenParameterSpec and BiometricPrompt paths; real auth test pending |
| STO-04 | Identity, ratchet, replay, pairing, contact, and pending records are authenticated-encrypted | 16 | Pending | Values/session replay ledger use AES-GCM, but hashed replay index/timestamps remain plaintext; minimize/authenticate and run stolen-DB test |
| STO-05 | No master/private key is stored in preferences, assets, source, BuildConfig, logs, or exported files | 16, 23 | Implemented | DEK exists only wrapped file/in-memory lease by source review; APK/storage scan pending |
| STO-06 | Vault policies include immediate/30 s/1 min/5 min with 1 min default | 16 | Implemented | `VaultLockController` and 3 unit tests; settings UI/device timing pending |
| STO-07 | Vault locks on boot, screen lock, manual action, timeout, and key invalidation | 16 | Implemented | Runtime lifecycle/controller paths exist; instrumentation pending |
| STO-08 | Keystore invalidation fails closed and requires explicit recovery/re-pairing | 16, 25 | Implemented | Reset is exposed only after observed invalidation, requires destructive confirmation, and removes encrypted records/replay before the wrapped key; device invalidation test pending |
| STO-09 | `allowBackup=false` and data extraction rules exclude all CipherBoard data | 16, 27 | Implemented | Source manifest/rules reviewed; merged APK, `bmgr` and transfer test pending |
| STO-10 | v1 has no identity, ratchet, secret, message-key, or plaintext-history export/restore | 16, 18 | Implemented | No export/restore surface found; final intent/UI/APK review pending |
| STO-11 | Database corruption is detected without plaintext fallback or silent identity reset | 25 | Implemented | AEAD/strict codec failures exist; full DB/WAL corruption matrix pending |

## 9. Private Mode and Keyboard

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| IME-01 | Ordinary HeliBoard English/Russian/emoji/symbol/Unicode input remains functional | 5, 26, 31 | Pending | Debug app survives the fixed locale change before IME selection; actual ordinary-keyboard regression/instrumentation suite remains |
| IME-02 | Shield action toggles a CipherBoard-owned Private panel above the keys without navigating away from the host | 11 | Implemented | Embedded controller/layout and emulator visual inspection show an in-IME panel; complete UI instrumentation pending |
| IME-03 | Software-key plaintext stays in the local draft and never reaches host `InputConnection`, composing region, or simulated key events | 11, 31 | Implemented | Bounded local connection, early routing gates and exact-token host scope have unit/source coverage; hostile host `EditText` instrumentation remains required; hardware keyboards are explicitly unsupported for Private drafts |
| IME-04 | Only exact persisted ciphertext is committed with `commitText()` after explicit encryption | 11 | Implemented | One-shot pending handoff is bound to originating host package/UID/editor and exact `InputBinding.connectionToken`; framework capture test pending |
| IME-05 | Plaintext remains visible after successful ciphertext insertion and clears on explicit clear/close, host-field change, lock, screen-off, or IME destruction | 11, 15 | Implemented | Embedded controller owns and wipes the bounded draft; lifecycle/heap/field-switch instrumentation pending |
| IME-06 | Private mode disables personalized learning, user dictionary, input history, persistent drafts, and clipboard history | 11, 23 | Implemented | Central secure marker disables learning/suggestions/history and blocks copy/cut/paste/share/voice/IME-picker paths; preference-enabled device sentinel test pending |
| IME-07 | Plaintext is absent from saved state, long-lived ViewModels, intents, preferences, files, cache, and database | 11, 23 | Implemented | No-save/no-ViewModel/no-plaintext-extra/persistence path by source; sentinel scan pending |
| IME-08 | Embedded Private panel shows contact verification, vault state, size estimates, clear/close/encrypt controls | 11 | Implemented | Controls/statuses present even without paired contacts; UI/accessibility test pending |
| IME-09 | Password fields show an explicit warning; no automatic encryption/commit occurs | 26 | Implemented | Embedded controller requires acknowledgement; instrumentation pending |
| IME-10 | Layout handles large fonts, landscape, light/dark theme, optional dynamic color, English/Russian strings, and RTL rendering | 21, 22 | Pending | Screenshot/accessibility/localization matrix |
| IME-11 | Exact host binding token scopes the Private panel; only one metadata-matching token rebind is allowed after non-exported Vault unlock | 11, 17 | Implemented | `EmbeddedHostScope` unit coverage exists; Android reconnect/field-collision instrumentation pending |
| IME-12 | Private panel uses `FLAG_SECURE`; its RAM/UI clearing is documented as best effort, not guaranteed zeroization | 15, 24 | Implemented | Emulator capture was black and documentation states JVM/UI limits; physical screenshot/heap evidence pending |
| IME-13 | Physical keyboard bypass is not treated as protected Private input | 11, 26 | Implemented | UI/docs instruct use of on-screen keys; host-level physical-key sentinel and GrapheneOS device test pending |

## 10. Decryption and Protected Viewer

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| DEC-01 | `ACTION_PROCESS_TEXT` validates ciphertext, is read-only, and never returns plaintext to source app | 14 | Verified | API 36 instrumentation returns `RESULT_CANCELED` with no data and leaves the host text unchanged while opening the protected viewer |
| DEC-02 | IME selected-text action decrypts only selected ciphertext; fallback copies ciphertext only | 14 | Implemented | API 36 explicit clipboard fallback reads ciphertext and retains the original clip; real IME selected-text host path remains untested |
| DEC-03 | Clipboard never receives plaintext automatically | 14, 23 | Implemented | Instrumented fallback retains ciphertext unchanged and viewer plaintext is not copied; broader listener/history device test pending |
| DEC-04 | Wrong-contact, tampered, truncated, replayed, incomplete, and oversized inputs fail closed | 7, 12, 25 | Implemented | Native/runtime error mapping and parser tests; integrated negative suite pending |
| DEC-05 | Viewer sets `FLAG_SECURE` and prevents normal screenshots | 15 | Implemented | API 36 instrumentation asserts the real viewer window has `FLAG_SECURE`; a separate `FLAG_SECURE` test screencap is fully black, while secure-viewer-specific screenshot/capture remains pending |
| DEC-06 | Viewer is excluded/blanked in recent-app previews | 15 | Implemented | Manifest exclusion plus Android 13+ recents suppression; device evidence pending |
| DEC-07 | Viewer clears/closes on background, screen off, lock, timeout, and immediate-hide action | 15 | Implemented | API 36 background test verifies display-lease close plus byte/char plaintext zeroization; screen-off/lock/timeout device matrix remains |
| DEC-08 | Plaintext selection/copy/share/notification/assistant/content-capture/autofill is disabled by default | 15, 23 | Implemented | Drawing-only inaccessible view and suppression callbacks; UI/system-service tests pending |
| DEC-09 | Secure reply opens composer for authenticated contact without plaintext intent/state transfer | 14, 15 | Implemented | Internal contact-ID token only; intent/memory test pending |
| DEC-10 | UI explains that `FLAG_SECURE` and Accessibility restrictions are not absolute protection | 3, 15 | Implemented | English/Russian security screen contains explicit limitations; bilingual UX review pending |

## 11. Plaintext, Memory, and Diagnostic Leakage

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| LEAK-01 | No plaintext in logcat, crash output, analytics, breadcrumbs, traces, or Gradle/test snapshots | 23 | Pending | Sentinel plaintext scan across runtime/build outputs |
| LEAK-02 | No full ciphertext, QR payload, private/session key, full fingerprint, Safety Number, or contact name in logs | 23 | Pending | Structured log review and sentinel tests |
| LEAK-03 | Release debug logging is disabled and user errors omit stack traces/content | 21, 23 | Pending | Release build/config/UI test |
| LEAK-04 | No plaintext in clipboard, notifications, intents, filenames, temp/cache files, normal Room tables, or recent previews | 23 | Pending | Cross-surface sentinel test |
| MEM-01 | Rust minimizes clones and zeroizes owned secret buffers where possible | 24 | Implemented | `SecretBytes`/zeroize paths and redacted errors; external/fuzz review pending |
| MEM-02 | Kotlin uses clearable arrays where possible and clears/cancels short-lived plaintext state | 24 | Implemented | Owned-secret/wipeable viewer/composer cleanup paths; heap/lifecycle test pending |
| MEM-03 | No plaintext/key in singleton, static field, or long-lived coroutine | 24 | Pending | Static analysis and lifecycle review |
| MEM-04 | JVM/UI/JNI zeroization limitations are documented without guaranteed-RAM-erasure claims | 24 | Implemented | `THREAT_MODEL.md`; UI/README review pending |

## 12. Android Permissions and Components

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| AND-01 | Manifest excludes Internet/network, package installation, Contacts, SMS, package-query, overlay, and Accessibility-service permissions | 19, 28 | Verified | The pre-public local signed candidate passed `aapt`/`apkanalyzer`/policy checks; repeat `INTERNET` and `REQUEST_INSTALL_PACKAGES` checks against the final public artifact |
| AND-02 | Camera is the only planned dangerous runtime permission and is requested just in time | 19 | Implemented | Signed-candidate permission evidence and explicit Scan-triggered launcher are present; physical just-in-time grant/deny/revoke remains pending |
| AND-03 | Sensitive activities/services/providers are non-exported unless required and strictly validate callers/input | 27, 28 | Implemented | Secure components are non-exported except launcher/process-text and the pre-public local candidate's APK exported-shape policy passed; deeper final intent validation remains pending |
| AND-04 | Process-text component is exported only as Android requires and treats all input as hostile | 14, 27 | Implemented | Strict action/MIME/size/ASCII/envelope path and no result replacement; malicious-intent instrumentation pending |
| AND-05 | PendingIntents, if any, are immutable/mutable only as necessary and explicit | 27 | Pending | Static manifest/source scan |
| AND-06 | Cleartext traffic is disabled even though no network capability exists | 27 | Verified | Source policy and pre-public local signed-candidate merged-APK policy passed; repeat for the final public artifact |
| AND-07 | No deep link, path traversal, unsafe file provider, ZIP extraction, or broad package visibility surface | 27 | Pending | Static and hostile-intent tests |
| AND-08 | Native libraries use supported ABI set and release hardening | 27, 30 | Pending | ELF inspection for `arm64-v8a` and test `x86_64` |

## 13. Tests and Security Tooling

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| TST-01 | Alice/Bob pairing, Safety Number, bidirectional first messages, and 1000-message sequence pass | 25 | Implemented | 27-test native suite covers these paths and matching numeric/word comparison; Android integration pending |
| TST-02 | Reorder, skip, replay, tamper, truncate, trailing data, wrong version/contact, concurrency pass | 25 | Implemented | Native regression coverage reported; complete concurrency/Android report pending |
| TST-03 | Empty, long, Unicode, maximum multipart, and over-limit cases pass | 25 | Implemented | Native boundary coverage includes the 48-byte SMS/153-character limit; Android product intentionally rejects empty compose and UI/device matrix remains |
| TST-04 | Crash matrix, restart replay, and outbound delivery-state tests pass | 17, 25 | Implemented | Targeted 3-boundary actual-SIGKILL matrix, 2 close/reopen atomicity tests and v0.2 `READY`/`COMMIT_UNCERTAIN` unit cases exist; individual SQLite statements and ambiguous real `commitText()` acknowledgement remain uncovered |
| TST-05 | Delete, re-pair, identity change, DB corruption, Keystore invalidation, StrongBox/TEE fallback pass | 25 | Pending | Storage/device report |
| TST-06 | Parser property tests and fuzzing complete without panic or unbounded allocation | 25 | Implemented | Reproducible three-seed cargo-fuzz target completed 601,574 ASan inputs in 31 seconds with zero crashes/timeouts; broader pairing/JNI campaigns pending |
| TST-07 | IME regression, embedded Private panel, process-text, selection, clipboard, lifecycle, and viewer Android tests pass | 26 | Implemented | Existing API 36 AOSP 7/7 covers process-text/viewer/clipboard and vault fault scope; local draft/routing unit tests pass, while full IME/private-panel/live-camera E2E remains absent |
| TST-08 | Tests run on GrapheneOS without Google Play | 20, 26 | Pending | Device/build/version evidence |
| TOOL-01 | Gradle lint and unit tests pass | 27 | Implemented | Full debug unit tasks and release lint for `app`/`crypto-core`/`pairing`/`secure-storage` pass after API 23 compatibility fixes; rerun/archive for exact release commit |
| TOOL-02 | Kotlin formatting/static analysis pass | 27 | Implemented | Fork-wide changed-Kotlin format gate and Android lint pass; independent detekt-equivalent review remains desirable |
| TOOL-03 | `cargo fmt --check`, clippy with warnings denied, and Rust tests pass | 27 | Implemented | Current work session reported fmt/clippy and 27 native tests passing; rerun/archive on clean release commit |
| TOOL-04 | Dependency audit/locking/SBOM checks pass or exceptions are risk-accepted with expiry | 27 | Verified | Pre-public local signed candidate PASS: pinned official OSV-Scanner v2.4.0 hash, fresh offline Maven/crates.io DBs, all 255 SBOM packages, exit 0/zero findings; final public tag must repeat and review its own `VULNERABILITY_SCAN.json` |
| TOOL-05 | Secret scan and plaintext sentinel scan pass | 23, 27 | Implemented | Fail-closed source/network/telemetry/secret scanner passes; runtime/build-output plaintext sentinel evidence remains pending |

## 14. Release Artifact and Signing

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| REL-01 | Debug and release scripts are deterministic, fail closed, and do not print signing secrets | 29 | Verified | A clean pre-public local signed candidate completed the full scripted pipeline; final public tag must repeat it |
| REL-02 | Release key is generated/stored outside Git with no password in repository or console output | 29 | Verified | The candidate build consumed pre-existing external signing material after local access checks; no secret value is retained as evidence or in Git |
| REL-03 | Signing key backup/continuity warning is documented; existing key is never overwritten | 29 | Implemented | `RELEASE.md` documents backup/continuity and scripts only consume existing external material; final operator walkthrough pending |
| REL-04 | Release APK is not debug-signed, debuggable, or test-only | 28 | Verified | The pre-public local signed candidate passed certificate and merged-manifest policy; repeat for the public release tag |
| REL-05 | `apksigner verify --verbose` succeeds | 28, 31 | Verified | Candidate pipeline passed `apksigner` verification with the pinned release certificate; regenerate evidence for the final public artifact |
| REL-06 | `aapt` and `apkanalyzer` permission lists contain no forbidden permission | 28, 31 | Verified | Candidate pipeline passed both permission views with no INTERNET; repeat remains an unconditional publication blocker |
| REL-07 | Exported components and intent filters pass final APK review | 27, 28 | Verified | Candidate scripted merged-manifest/exported-shape policy passed; repeat and manually review the final public artifact |
| REL-08 | APK scan finds no Firebase, analytics, crash, ad, Play Services, test keys, or dynamic loading | 28 | Verified | Candidate APK policy scan passed; repeat for the final public artifact |
| REL-09 | `dist/` contains both APKs, release SHA-256, SBOM, vulnerability report, artifact hashes, notices, source archive, and complete build info | 30 | Verified | The pre-public local candidate evidence bundle contains the required outputs but is untracked/unpublished; regenerate them for the final public tag |
| REL-10 | Build info records commit, upstream, toolchain, SDK/NDK/Rust/crypto versions, ABI, digest, cert, and permissions without secrets | 30 | Verified | The pre-public local candidate generated the required non-secret provenance; the final public tag must publish its own `BUILD_INFO.txt` |
| REL-11 | Release APK installs and launches, and CipherBoard can be enabled as an IME | 31 | Pending | `adb install` and device acceptance log |
| REL-12 | Release SHA-256 and certificate fingerprint are independently recomputed | 28, 30 | Verified | Candidate pipeline recomputed both and enforced the reviewed public `SIGNING_CERTIFICATE_SHA256` pin; repeat against the final public artifact |

## 15. UX, Localization, and User Guidance

| ID | Requirement | Req. | State | Evidence / next evidence |
| --- | --- | --- | --- | --- |
| UX-01 | English and Russian resources cover all user-facing text, errors, plurals, and accessibility descriptions | 21, 22 | Implemented | English and per-app `ru-RU` Home hierarchies fit without overlap; Russian Home also fits landscape at `font_scale=1.3`; remaining screens, font 2.0 and RTL matrix pending |
| UX-02 | Security screen states protections and all explicit limitations in plain language | 3, 21 | Implemented | English/Russian security screen covers stated threats and residual risks; device/UX review pending |
| UX-03 | Contact/session states are distinct and understandable | 21 | Implemented | Verified/unverified/key-changed/pairing/session states are rendered in home, the Private panel and contact details; localization/device UX review pending |
| UX-04 | No stack traces, raw crypto errors, or misleading assurances are shown | 3, 21 | Implemented | Secure UI maps fixed errors and states no independent audit; negative-path/string scan pending |
| UX-05 | Installation guide covers trusted source, SHA-256, IME enablement, Network/Sensors denial, strong lock, locked bootloader, and Accessibility risk | 20 | Pending | GrapheneOS guide review |
| UX-06 | Pair/send/decrypt/update/re-pair flows and no-history consequences are documented | 9, 18, 33 | Pending | End-to-end documentation test |
| UX-07 | High-risk guidance requires independent applied-crypto and Android-security review | 33 | Implemented | `THREAT_MODEL.md`; final report/UI review pending |

## Release Gate

Publication is blocked if any artifact-critical item remains `Pending` or merely
`Implemented`. A locally signed candidate does not waive this rule for a changed
commit: every artifact gate must be repeated and tied to the final tag's
`BUILD_INFO.txt`. The previous broad instrumentation/process-kill evidence
blocker is closed for the seven recorded API 36 AOSP tests; the narrower untested
SQLite-statement, real host-ack and complete IME/private-panel/camera paths are not
represented as passed. Rows explicitly requiring independent audit or physical
GrapheneOS/StrongBox/TEE/camera evidence are residual assurance prerequisites
before high-risk use; their absence is not a known critical code defect.

Automated/artifact hard blockers include:

- a forbidden permission, especially `android.permission.INTERNET`;
- unsigned, debug-signed, debuggable, or test-only production APK;
- missing final-artifact manifest/signature/hash evidence;
- failing cryptographic, atomicity, replay, parser, storage, leakage, IME, or
  protected-viewer test;
- plaintext observed in a host field, clipboard, log, persistent store,
  notification, recent preview, or screenshot through normal Android APIs;
- unpinned or vulnerable crypto dependency without a documented, reviewed
  resolution;
- a mandatory Google Play dependency or inability to build the required
  `arm64-v8a` artifact;
- missing GPLv3 source/notices or missing SBOM/build provenance;
- claim of independent audit when no such review occurred.

At release, archive the checklist together with the exact Git commit, APK
SHA-256, signing certificate fingerprint, tool versions, and test reports. The
statement that automated tests passed must identify the exact artifact and must
remain separate from any claim of independent audit.
