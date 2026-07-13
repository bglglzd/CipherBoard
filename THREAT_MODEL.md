# CipherBoard Threat Model

**Status:** design-time threat model, 2026-07-13  
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

## 1. System and Security Objective

CipherBoard is a serverless Android input method and companion UI derived from
HeliBoard. Two users establish a one-to-one cryptographic session by physically
scanning each other's QR codes and comparing a Safety Number. The sender writes
plaintext only in CipherBoard's protected composer. CipherBoard commits only an
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

The physical QR exchange reduces remote interception but does not prevent a
nearby attacker from replacing a displayed QR code, substituting an APK, or
convincing users to skip comparison. Verification is complete only after both
users compare the Safety Number and explicitly confirm it. Imported, expired,
consumed, duplicated, oversized, malformed, or version-incompatible offers must
fail without creating a trusted contact.

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
4. Commit the transaction before calling `InputConnection.commitText()`.
5. Clear the plaintext composer after the commit attempt and retain/complete the
   pending record according to a deterministic recovery policy.

Android `InputConnection` does not provide a durable, cross-process exactly-once
acknowledgement that the host saved or sent text. A crash after state commit may
therefore require reinserting the same pending ciphertext, never encrypting the
plaintext again with rolled-back state. This can cause duplicate transport
delivery; the receiver must classify it as replay rather than expose plaintext
twice.

For receive:

1. Parse and authenticate the complete ciphertext.
2. Decrypt into a short-lived buffer and obtain advanced receive state.
3. Atomically store that state plus an encrypted pending-display record.
4. Show plaintext only after the transaction commits.
5. Delete the pending-display record when the protected view closes, because v1
   does not keep plaintext history or message keys for later convenience.

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
Keystore, attempted in StrongBox first, and falls back without crashing to TEE.
The UI reports the actual security level; it must not label a software or TEE
key as StrongBox. The key is non-exportable and gated by
`BIOMETRIC_STRONG` or device credential.

The default vault timeout is one minute, with immediate, 30-second, one-minute,
and five-minute policies. The vault locks after boot, screen lock, manual lock,
authentication timeout, detectable lock-screen changes, and key invalidation.
Invalidated or missing keys produce a controlled unrecoverable-vault/re-pairing
flow, not silent identity regeneration or plaintext fallback.

`android:allowBackup="false"` and current data extraction rules must exclude all
records from cloud backup and device transfer. v1 provides no secret, ratchet,
or history export. Clearing app data/reinstalling destroys the identity and
requires pairing again. Secure deletion is best effort: Android flash storage,
filesystem journaling, wear levelling, and OS caches prevent a promise that old
physical blocks are overwritten.

## 11. Plaintext UI and IME Isolation

Normal HeliBoard input remains normal keyboard input. Secure mode is a distinct
state entered by an explicit shield action. It must warn before use in password
fields and must never auto-commit ciphertext.

In secure mode:

- plaintext is entered only into CipherBoard-owned UI;
- no plaintext is sent to the host `InputConnection`, including composing text
  and key-event simulation;
- only ciphertext is passed with `commitText()` after explicit encryption;
- clipboard access is prohibited for plaintext; ciphertext-only fallback is
  permitted after an explicit action;
- personalized learning, user dictionary updates, input history, drafts, and
  clipboard history are disabled;
- plaintext is excluded from `SavedStateHandle`, instance state, ViewModels
  that outlive the view, intents, files, databases, caches, and static fields;
- plaintext fields and short-lived buffers are cleared on success, cancel,
  timeout, backgrounding, lock, and view destruction.

Ordinary static Russian/English dictionaries may be used locally, but secure
input must not train or update personalized data.

`ACTION_PROCESS_TEXT` is read-only from the source application's perspective.
CipherBoard receives ciphertext, validates it, unlocks the vault, and displays
plaintext without returning replacement text. Selected-text decryption through
the IME follows the same rule. Ciphertext copied by the user is untrusted parser
input; plaintext is never copied automatically.

## 12. Protected Viewer Limitations

The plaintext viewer must use `FLAG_SECURE`, exclude its task from recent-app
previews, disable sharing/copying/selection by default, suppress notifications,
assistant/content-capture/autofill exposure, clear on background or screen off,
and close after a configurable timeout. Replying opens an empty secure composer
bound to the authenticated contact; plaintext is not transferred as an intent
extra.

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

Kotlin/Java should prefer `ByteArray` and `CharArray` for application-managed
secret buffers, clear them, cancel work when the protected view closes, and
avoid singletons or long-lived coroutines. Nevertheless, Android text widgets,
IME internals, immutable `String` objects, JNI marshalling, garbage collection,
compiler copies, and crypto-library allocations can leave unaddressable copies
in process memory. Clearing references and arrays reduces exposure time; it is
not guaranteed RAM erasure. The UI and documentation must not claim otherwise.

## 14. Logs, Diagnostics, and Supply Chain

CipherBoard has no remote analytics, crash reporting, advertising, dynamic code
loading, or WebView. Release logging excludes plaintext, full ciphertext, QR
payloads, private keys, session state, full fingerprints, Safety Numbers, and
contact names. Diagnostic events use coarse error codes and random test IDs.
Stack traces are not shown to users.

The final manifest must contain no Internet, network-state, contacts, SMS,
package-query, overlay, or Accessibility-service permission. Camera is requested
only when the user explicitly starts local QR scanning. GrapheneOS Network
denial is defense in depth and not a substitute for removing network permission
and network-capable dependencies.

Dependencies are pinned and locked, notices and GPLv3 obligations are retained,
and an SBOM is produced. Release verification includes manifest inspection,
signature verification, certificate fingerprint, SHA-256, non-debuggable/test
flags, exported-component review, dependency vulnerability review, and scans
for Firebase, Play Services, analytics, crash, advertising, test keys, secrets,
and dynamic loading.

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

Recovery choices are limited to retrying the same pending ciphertext, deleting
an unfinished pairing, locking the vault, deleting a contact/session, or
explicit physical re-pairing.

## 17. Required Validation and Audit Status

Unit, property, fuzz, Android instrumentation, crash-injection, manifest,
dependency, and signed-APK tests defined in `TEST_PLAN.md` and
`SECURITY_CHECKLIST.md` must pass for the exact release commit and artifact.
Testing on a GrapheneOS device without Sandboxed Google Play remains necessary.

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
