# CipherBoard Threat Model

**Status:** design-time threat model, 2026-07-14
**Scope:** CipherBoard v1: one-to-one offline pairing and encrypted text
transport through untrusted applications  
**Assurance:** no independent product security audit has been performed

This document defines the intended security boundary and the controls that the
implementation must satisfy. A control described here is not evidence that it
has been implemented or tested. Current implementation and verification state
is tracked in `SECURITY_CHECKLIST.md`.

CipherBoard must not be described as unbreakable, risk-free, absolutely secure,
or "military grade." It aims to reduce specific, documented risks while
retaining important residual risks.

### Current implementation coverage

As of this snapshot, the source tree implements encrypted vault records,
Keystore StrongBox-first generation with fallback and reported security level,
atomic send/receive record transactions, an embedded Private mode panel inside
the IME, selected-text/`ACTION_PROCESS_TEXT` decryption, a protected viewer, and an
offline QR codec/scanner. A non-exported protected two-QR activity now joins the
native offer/response APIs to encrypted one-shot state for both roles and to
contact creation only after explicit local Safety Number confirmation. Contact
details support rename, reverify, session destruction, delete and re-pair. This
reduces implementation risk but is not release evidence by itself.

The pairing/contact source has JVM state-machine/navigation coverage, bounded
orphan/expiry cleanup, explicit unfinished-pairing deletion and blocking
identity-change handling. Targeted API 36 AOSP instrumentation now covers seven
process-text/viewer/clipboard/vault tests, including three real remote-process
SIGKILL boundaries around outbound and inbound storage commits. It does not
cover pairing-specific process death, crashes between individual SQLite
statements, the real `InputConnection.commitText()` acknowledgement window, or
a complete IME/private-panel/live-camera flow. Live two-device camera exchange and
GrapheneOS operation remain residual platform validation before high-risk use.
Outbound publication uses a contact-bound exact pending ciphertext, a one-shot
handoff scoped to the originating host/editor and exact connection token, and
a durable delivery-uncertain state that cannot auto-retry. Inbound recovery
requires the exact ordered ciphertext digest and retains the encrypted pending
display until the viewer has actually rendered it. Exact capability, routing,
inner-binding and assembly-integrity decisions are recorded in
`CRYPTO_PROTOCOL.md`; independent review remains an assurance prerequisite, not
evidence of a known defect.

Source inspection found no `INTERNET` or `ACCESS_NETWORK_STATE` declaration,
runtime HTTP client, Firebase/Play Services/analytics/crash/ad SDK, WebView, or
dynamic loader. The CameraX video/media dependency path is excluded; the
manifest disables backup, excludes every extraction domain, and denies
cleartext traffic. A pre-public local signed candidate passed the scripted APK
policy, but its evidence is untracked and unpublished. That does not replace
independent permission and dependency review of the exact published artifact,
and the gate must be repeated for the final public tag.

## 1. System and Security Objective

CipherBoard is a serverless Android input method and companion UI derived from
HeliBoard. Two users establish a one-to-one cryptographic session by physically
scanning each other's QR codes and comparing a Safety Number. The sender writes
plaintext only in CipherBoard's embedded Private panel. CipherBoard commits only an
ASCII ciphertext envelope to the host application. The recipient passes that
ciphertext back to CipherBoard for decryption and views plaintext only in a
protected CipherBoard window.

The principal confidentiality boundary is between CipherBoard and the external
transport application. SMS clients, messengers, email clients, carriers,
messenger servers, and their backups are expected to see ciphertext and
transport metadata, but not plaintext or session keys.

## 2. Assets

| Asset | Required property |
| --- | --- |
| User plaintext | Confidential inside CipherBoard; never committed to the host field, clipboard, logs, notifications, saved state, or ordinary storage |
| Identity private keys | Confidential, integrity protected, non-exported from the vault, destroyed when app data is cleared |
| Olm/Double Ratchet session state | Confidential, integrity protected, crash-consistent, never backed up or cloned |
| Current, used, and skipped message keys | Minimal retention, bounded skipped-key storage, deletion after use as supported by the crypto library |
| Android Keystore wrapping key | Non-exportable; StrongBox preferred, TEE fallback reported accurately |
| Contact-to-identity binding | Integrity protected; identity changes must cause a blocking key-change state, never silent replacement |
| Pairing transcript and verification state | Authentic and bound to both identities, the one-time offer, and protocol version |
| Pending send/display records | Encrypted, transactional, bounded, recoverable without reusing ratchet state |
| Local contact names and settings | Local-only and protected at rest; names are not cryptographic identities |
| Release signing key | Confidential outside the repository; continuity protected by an offline backup process |

Public identity keys, fingerprints, Safety Numbers, ciphertext, routing/session
tags, message sizes, timestamps, and transport endpoints are not treated as
secret plaintext. Some remain privacy-sensitive and must still not be logged.

## 3. Trust Boundaries and Dependencies

CipherBoard relies on:

- the installed APK being the intended, correctly signed build;
- Android/GrapheneOS enforcing process isolation, Keystore policy, verified
  boot, lock-screen authentication, and storage encryption;
- a pinned, reviewed cryptographic library implementing Olm/Double Ratchet;
- Android's cryptographically secure random source as consumed by that library;
- users comparing the Safety Number over the physical pairing ceremony;
- the QR decoder operating locally with strict input limits;
- the external application preserving the ciphertext text sufficiently for the
  receiver to select or copy it.

The external input field, `InputConnection`, clipboard, SMS/messenger/email
application, network, carrier, messenger service, cloud backup, and message
recipient account are outside the trusted boundary. Camera input and selected
text received through Android intents are attacker-controlled inputs.

Rust/JNI or UniFFI is also a trust boundary. Its API must be narrow, length
checked, fail closed, and avoid representing secret keys as Kotlin `String`
values. FFI does not make calling Kotlin code or library internals memory-safe.

## 4. Adversaries and Threats Addressed

The design is intended to address the following threats when the assumptions in
this document hold:

| Threat | Required response |
| --- | --- |
| Carrier, SMS server, or messenger server reads content | It receives only authenticated ciphertext |
| External messaging account is compromised | Stored transport content remains ciphertext; metadata and future messages typed on a compromised device are not protected |
| Network interception or modification | AEAD/session authentication rejects changed or forged ciphertext |
| Old ciphertext is replayed | Used message keys/message IDs and persisted receive state reject duplicate delivery |
| Messages are delayed, missing, or reordered | Bounded skipped-key handling supports permitted out-of-order delivery without accepting replay |
| Ciphertext is routed to the wrong contact | A non-identifying session/routing tag selects a candidate session; cryptographic authentication must still succeed or the message is rejected |
| App database is copied from a locked phone | Identity and session records remain encrypted under a user-authenticated, non-exportable Android Keystore key |
| Android cloud backup copies secrets | Backup and device-to-device extraction rules exclude all CipherBoard data; ratchet state is not restorable in v1 |
| Plaintext leaks through normal keyboard learning | Personal learning, user-dictionary writes, history, and clipboard history are disabled in secure mode |
| Plaintext leaks through application diagnostics | Plaintext and other sensitive values are excluded from logs, analytics, crash SDKs, traces, and filenames |
| Parser or QR input attempts memory exhaustion | Strict byte, field, nesting, part-count, and allocation limits reject input before expensive processing |
| Pairing offer is replayed | Offer ID, nonce, expiry, one-time-key state, and consumed status reject reuse |
| Peer identity changes after reinstall/reset | Existing contact enters a critical `Key changed`/`Pairing required` state until a new physical pairing is completed |

Sender authentication is meaningful only after users validate the pairing
Safety Number. Before that confirmation, the session is cryptographic but not
verified against a man-in-the-middle during pairing.

## 5. Explicitly Outside Full Protection

CipherBoard cannot fully protect against:

- an attacker controlling an unlocked device or reading its live screen;
- root access, kernel/OS exploitation, compromised firmware, or a broken
  Keystore/StrongBox implementation;
- a malicious or substituted CipherBoard APK, malicious build toolchain, or
  stolen release signing key;
- a camera recording the screen or a person reading over the user's shoulder;
- a malicious Accessibility, screen-reader, input, device-admin, or similar
  privileged service;
- traffic analysis and metadata retained by the external transport;
- physical coercion or disclosure of the device credential;
- defects in the selected cryptographic library or its dependencies;
- implementation defects, especially before independent Android and applied
  cryptography review.

The product must present these limitations in plain language in its Security
screen. Security-sensitive use should not assume they have been eliminated.

## 6. Cryptographic Protocol Boundary

The intended v1 protocol uses a pinned release of `matrix-org/vodozemac` for
Olm/Double Ratchet unless an ADR documents an objective integration or security
blocker and selects another maintained, reviewed implementation. CipherBoard
must not implement Curve25519, Ed25519, AEAD, HKDF, a ratchet, a random number
generator, a hash, or a signature scheme itself.

The integration must preserve:

- a unique derived message key per ratchet step;
- forward secrecy and DH/symmetric ratcheting as provided by Olm;
- authenticated encryption and failure on modification;
- bounded out-of-order/skipped message-key storage;
- deletion of used message keys according to the library API;
- explicit session reset and re-pairing on identity change;
- fixed protocol/library versions and reproducible dependency resolution.

Use of reviewed primitives does not establish the security of the surrounding
pairing, storage, transaction, FFI, parser, or UI code. Published audit claims,
security policies, version provenance, and GPLv3/Apache-2.0 license compatibility
must be recorded in the crypto ADR and notices without overstating their scope.

## 7. Identity and Physical QR Pairing

An identity is generated locally at first run. A phone number, email address,
username, Android ID, IMEI, serial number, device model, advertising ID, IP
address, system account name, location, or system contact is not part of it.
The owner's display name and contact aliases are local metadata and must not
silently enter a QR payload.

A pairing offer must be random, single-use, expiring, and deletable. It contains
only the protocol version, pairing ID, public identity/pre-key material,
capabilities, expiry, nonce, and material necessary to establish and bind the
session. The response binds both identities and the entire offer/response
transcript. Both devices derive the same transcript hash, numeric Safety Number,
and short emoji/word representation. These are two renderings of one value, not
independent authentication mechanisms.

The importer verifies the signed absolute expiry and rejects an offer whose
remaining lifetime exceeds the protocol maximum plus the bounded clock
tolerance. This prevents a producer from silently extending an offer
indefinitely. Clock rollback beyond the accepted tolerance fails closed; no
wall-clock check can be made rollback-proof against a compromised OS.

The physical QR exchange reduces remote interception but does not prevent a
nearby attacker from replacing a displayed QR code, substituting an APK, or
convincing users to skip comparison. Verification is complete only after both
users compare the Safety Number and explicitly confirm it. Imported, expired,
consumed, duplicated, oversized, malformed, or version-incompatible offers must
fail without creating a trusted contact.

The current Android implementation stages encrypted one-shot state for both
roles, cleans up expired/orphaned active state in bounded batches, requires an
explicit confirmation action on each device before creating a verified
contact, and treats a changed identity as a blocking state until explicit
physical re-pairing and Safety Number confirmation. Its 80-digit numeric value
and eight-word code are two deterministic representations of the same
transcript hash. The earlier blanket absence of process-kill evidence is closed
only for the three recorded vault boundaries. Pairing-specific process death
and live two-device camera validation remain untested prerequisites before
high-risk use; neither is represented as a pass by the narrower storage tests.

## 8. Transport Envelope and Metadata

The outer transport is an ASCII-safe, versioned `CB1:` envelope with strict,
deterministic binary encoding such as canonical CBOR. It may expose the minimum
needed for parsing and reassembly: protocol/envelope version, message type,
opaque routing/session tag, random message ID, Olm message type, part index,
part count, and capability flags. Contact names, fingerprints, Safety Numbers,
plaintext timestamps, reply subjects, and other sensitive metadata belong only
inside the authenticated encrypted payload.

The parser must reject invalid Base64url, padding where forbidden, duplicate
fields, unknown mandatory fields, trailing data, inconsistent message IDs,
invalid part indexes, excessive part counts, oversized input, and recursion or
allocation beyond fixed limits. Unknown optional fields may be retained or
ignored only as the version rules define. Multipart reassembly is bounded and
order independent, and decryption starts only when every consistent part is
present.

UTF-8 plaintext is encrypted byte-for-byte without normalization. Rendering may
apply the platform's normal bidirectional algorithm, but encryption/decryption
must preserve Russian, English, emoji sequences, combining marks, RTL text,
zero-width characters, mathematical symbols, newlines, and other valid Unicode.

No plaintext compression is enabled by default, avoiding compression side
channels and cross-implementation ambiguity.

## 9. Ratchet Atomicity and Crash Recovery

Advancing ratchet state and exposing a ciphertext must be one logical operation.
For send:

1. Load authenticated encrypted session state.
2. Encrypt once and obtain the advanced state.
3. In one durable database transaction, store the new state and an encrypted
   pending record containing the exact ciphertext/envelope.
4. Commit the transaction with outbound state `READY` before publication.
5. Validate the exact `InputBinding.connectionToken`, then atomically change the
   outbound record to `COMMIT_UNCERTAIN` before calling
   `InputConnection.commitText()`.
6. Delete the pending record only after an accepted insertion. A false return,
   exception, acknowledgement loss, or process death retains
   `COMMIT_UNCERTAIN` and must not trigger automatic retry.

Android `InputConnection` does not provide a durable, cross-process exactly-once
acknowledgement that the host saved or sent text. `READY` may be claimed once
before the Binder boundary, but `COMMIT_UNCERTAIN` is not automatically
reinserted: the host may already contain the ciphertext even when CipherBoard
did not receive a successful response. The user must inspect the transport.
Receiver replay protection rejects a duplicated ciphertext but cannot remove
duplicate text from the external application.

For receive:

1. Parse and authenticate the complete ciphertext.
2. Decrypt into a short-lived buffer and obtain advanced receive state.
3. Atomically store that state plus an encrypted pending-display record.
4. Show plaintext only after the transaction commits.
5. Bind the pending display to contact/message ID and the digest of the exact
   ordered ciphertext. An abandoned pre-render lease retains the encrypted
   record for exact retry; after successful render, closing the protected view
   deletes it because v1 keeps no plaintext history or message keys.

Crash-injection tests are required before/after every state transition. Database
transactions protect against ordinary process death and torn writes only when
the storage engine and durability settings are correctly used and tested.

Android does not offer ordinary applications a universal rollback-resistant
monotonic database counter. Disabling backup and binding records to a
non-exportable Keystore key prevents normal restore/cloning and makes another
device unable to unwrap the database. It does not guarantee detection of a
privileged same-device filesystem snapshot rollback. Root/OS-level snapshot
rollback remains a residual risk under the excluded device-compromise model.

## 10. Storage, Keystore, and Backup

All identity, session, replay, contact, pairing, and pending records must be
authenticated-encrypted at rest. The wrapping key is generated in Android
Keystore and attempted in StrongBox first. On StrongBox unavailability the app
may retry the default provider without crashing, but accepts that result only
when `KeyInfo` reports `TRUSTED_ENVIRONMENT`. Software and unknown levels fail
closed rather than being labeled as TEE or StrongBox. The UI reports the actual
accepted level. The key is non-exportable and gated by `BIOMETRIC_STRONG` or
device credential; real hardware/authentication evidence remains pending.

The default vault timeout is one minute, with immediate, 30-second, one-minute,
and five-minute policies. The vault locks after boot, screen lock, manual lock,
authentication timeout, detectable lock-screen changes, and key invalidation.
Invalidated or missing keys produce a controlled unrecoverable-vault/re-pairing
flow, not silent identity regeneration or plaintext fallback. Destructive reset
is exposed only after the runtime has observed key invalidation, requires an
explicit confirmation, and deletes encrypted records/replay state before
removing the wrapped key. Physical-device invalidation evidence remains pending.

`android:allowBackup="false"` and current data extraction rules must exclude all
records from cloud backup and device transfer. v1 provides no secret, ratchet,
or history export. Clearing app data/reinstalling destroys the identity and
requires pairing again. Secure deletion is best effort: Android flash storage,
filesystem journaling, wear levelling, and OS caches prevent a promise that old
physical blocks are overwritten.

The current database encrypts the bounded replay ledger inside the session
snapshot, but also keeps hashed record/replay indexes and timestamps in
plaintext SQLite columns for lookup and transactions. These values use random
internal IDs rather than names/raw keys, yet expose record counts and timing and
are not AEAD-authenticated. A copied locked-device database should not disclose
message text or session keys, but this local metadata leakage and tamper/DoS
surface remains open for minimization and device testing.

## 11. Plaintext UI and IME Isolation

Normal HeliBoard input remains normal keyboard input. Private mode is a distinct
state entered by an explicit shield action and rendered as a panel above the
same on-screen keys. It must warn before use in password fields and must never
auto-commit ciphertext.

In secure mode:

- on-screen key input is routed to a bounded, process-local CipherBoard draft;
- no plaintext is sent to the host `InputConnection`, including composing text
  and key-event simulation;
- only ciphertext is passed with `commitText()` after explicit encryption;
- clipboard access is prohibited for plaintext; ciphertext-only fallback is
  permitted after an explicit action;
- secure editor and IME actions block copy, cut, paste, share, voice input and
  IME-picker detours while plaintext is active;
- personalized learning, user dictionary updates, input history, drafts, and
  clipboard history are disabled;
- plaintext is excluded from `SavedStateHandle`, instance state, ViewModels
  that outlive the view, intents, files, databases, caches, and static fields;
- the plaintext remains visible after a successful ciphertext insertion so the
  sender can verify it, and is cleared on explicit clear/close, host-field or
  connection-token change, screen lock, IME destruction, or secure lifecycle
  exit;
- the exact non-null `InputBinding.connectionToken` scopes the host. Only the
  non-exported Vault-unlock return can perform one metadata-matching rebind;
- the IME window uses `FLAG_SECURE` while the panel is active.

Ordinary static Russian/English dictionaries may be used locally, but secure
input must not train or update personalized data.

Private mode does not control Android's physical-keyboard dispatch. The system
or host view may receive hardware key events directly, bypassing CipherBoard's
local draft connection. Users must enter Private drafts with the on-screen
keyboard; hardware-keyboard entry is outside the confidentiality boundary.

`ACTION_PROCESS_TEXT` is read-only from the source application's perspective.
CipherBoard receives ciphertext, validates it, unlocks the vault, and displays
plaintext without returning replacement text. Selected-text decryption through
the IME follows the same rule. Ciphertext copied by the user is untrusted parser
input; plaintext is never copied automatically.

## 12. Protected Viewer Limitations

The plaintext viewer must use `FLAG_SECURE`, exclude its task from recent-app
previews, disable sharing/copying/selection by default, suppress notifications,
assistant/content-capture/autofill exposure, clear on background or screen off,
and close after a configurable timeout. Replying opens an empty secure reply
surface bound to the authenticated contact; plaintext is not transferred as an
intent extra. This legacy reply path may use a protected CipherBoard activity;
the shield action itself remains embedded in the IME.

`FLAG_SECURE` blocks standard screenshots and display on many non-secure output
surfaces, but it is not an absolute screen-content guarantee. It does not stop a
physical camera, shoulder surfing, a compromised OS, root capture, vendor bugs,
or every Accessibility/privileged capture path. Accessibility exclusion can
reduce disclosure but cannot make a device with a malicious Accessibility
service trustworthy. TalkBack support should therefore be provided for
non-secret controls while secret message content is deliberately restricted;
this is a security/accessibility tradeoff that the UI must explain.

## 13. Memory and Zeroization Limits

Rust secret buffers should use `zeroize` where ownership and library APIs allow,
avoid unnecessary clones, never implement `Debug` with secret values, and never
place secrets in panic or error messages. Buffers crossing FFI must be length
checked and cleared by the owning side after use.

Rust release profiles use unwind semantics so the narrow JNI boundary can catch
an unexpected panic and return a fixed content-free error rather than aborting
the IME process. This is containment, not proof that every dependency is
panic-free. A pinned ASan/libFuzzer campaign ran the production envelope parser
for 601,574 inputs without a crash or timeout; pairing/inner/JNI targets and
longer scheduled campaigns remain required.

Kotlin/Java should prefer `ByteArray` and `CharArray` for application-managed
secret buffers, clear them, cancel work when the protected view closes, and
avoid singletons or long-lived coroutines. Nevertheless, Android text widgets,
IME internals, immutable `String` objects, JNI marshalling, garbage collection,
compiler copies, and crypto-library allocations can leave unaddressable copies
in process memory. Clearing references and arrays reduces exposure time; it is
not guaranteed RAM erasure. The UI and documentation must not claim otherwise.

## 14. Logs, Diagnostics, and Supply Chain

The reviewed source declares no remote analytics, crash reporting, advertising,
dynamic code loading, or WebView. The newly added secure paths do not contain
content-bearing log calls, and user errors are mapped to fixed messages. This
passed source and APK-marker policy on a pre-public local signed candidate, but
has not yet been demonstrated by a physical runtime leakage/sentinel campaign;
inherited logging and every error path remain part of that test. Plaintext,
full ciphertext, QR payloads, private keys, session state, full fingerprints,
Safety Numbers, and contact names must never enter diagnostics. Stack traces
must not be shown to users.

The final manifest must contain no Internet, network-state, contacts, SMS,
package-query, overlay, or Accessibility-service permission. Camera is requested
only when the user explicitly starts local QR scanning. GrapheneOS Network
denial is defense in depth and not a substitute for removing network permission
and network-capable dependencies.

CipherBoard also does not request `REQUEST_INSTALL_PACKAGES` and has no in-app
update client. Update discovery/download belongs to an external installer such
as Obtainium using GitHub Releases. That installer is a separate, networked
trust boundary; CipherBoard itself remains offline.

Rust dependencies are pinned and locked. Packageable Android dependency graphs
are strictly locked in `app/gradle.lockfile`; final notice and production SBOM
review remain required. The pre-public local signed candidate verified the
SHA-pinned official OSV-Scanner v2.4.0, fresh local Maven/crates.io databases,
and all 255 SBOM packages fully offline with zero findings; the final public
release tag must repeat it and publish its own evidence. The APK build
packages GPL/Apache/BlueOak/CC texts, consolidated BSD notices and provenance for
offline viewing, while release staging creates an exact-commit GPL source
archive. Release verification
includes manifest inspection, signature verification, certificate fingerprint,
SHA-256, non-debuggable/test flags, exported-component review, dependency
vulnerability review, and scans
for Firebase, Play Services, analytics, crash, advertising, test keys, secrets,
and dynamic loading.

The expected release-certificate SHA-256 is a reviewed public pin in
`SIGNING_CERTIFICATE_SHA256`. It is not secret, but a change is a security-
critical key-continuity event. Verification must reject an otherwise valid APK
signed by a different certificate.

## 15. Metadata and Availability Residual Risks

External transports still learn or infer sender/recipient accounts, message
time, size, frequency, conversation graph, IP/network information, device/app
telemetry collected by that transport, and that ciphertext-looking text was
sent. Multipart count reveals an approximate message length. Opaque routing tags
may permit correlation within their lifetime. CipherBoard cannot hide this
metadata because it does not operate the transport.

Observers of physical pairing can see public QR data and that two people paired.
The host application learns that ciphertext was inserted and can delete,
truncate, reformat, delay, reorder, duplicate, or refuse it. CipherBoard detects
many integrity/replay failures but cannot guarantee delivery, timeliness,
availability, or censorship resistance. Oversized-input rejection and bounded
state can allow an attacker to cause message rejection; availability is
secondary to memory safety and state integrity.

Forward secrecy and no-history mode mean a previously consumed message may not
be decryptable again. CipherBoard does not retain old message keys for
convenience. Users must not rely on CipherBoard v1 as an archival system.

## 16. Failure Handling

Cryptographic, parser, storage, authentication, identity-change, and session
errors fail closed. The application must not:

- display unauthenticated plaintext;
- silently reset a damaged session;
- retry encryption from stale state;
- accept a replacement identity key;
- expose secrets in an error message;
- fall back to unencrypted sending;
- treat a database or Keystore failure as an empty new vault without explicit
  destructive confirmation.

Recovery choices are limited to claiming an unattempted `READY` ciphertext once,
showing an explicit delivery-unknown result for `COMMIT_UNCERTAIN`, deleting an
unfinished pairing, locking the vault, deleting a contact/session, or explicit
physical re-pairing. An uncertain outbound operation must not be retried
automatically.

## 17. Required Validation and Audit Status

Unit, property, fuzz, Android instrumentation, crash-injection, manifest,
dependency, and signed-APK tests defined in `TEST_PLAN.md` and
`SECURITY_CHECKLIST.md` must pass for the exact release commit and artifact.
Testing on a GrapheneOS device without Sandboxed Google Play remains necessary.
Current parser evidence includes a bounded 601,574-input ASan/libFuzzer
campaign with no crash or timeout; it does not satisfy the remaining device,
full-codec, long-duration, or exact-release validation gates.

Automated tests can demonstrate selected behavior but cannot prove absence of
all leakage or cryptographic design defects. Before use in a high-risk setting,
the exact release should receive independent review by specialists in applied
cryptography, Android Input Method Framework, Android storage/Keystore, native
FFI, and reproducible release engineering, followed by remediation and a new
verified build.

**The build may use reviewed cryptographic primitives and pass automated tests,
but the complete product must not be considered independently audited until it
has been reviewed by an external applied cryptography and Android security
specialist.**
