# CipherBoard Architecture

Status: normative design for CipherBoard v1. Statements marked **MUST** are
release requirements, not claims about the current worktree. Implementation
status is tracked separately in `SECURITY_CHECKLIST.md`.

### Current implementation snapshot (2026-07-14)

The worktree currently contains four physical Gradle modules: `:app`,
`:crypto-core`, `:secure-storage`, and `:pairing`. `keyboard`, `secure-ui`, and
`transport-envelope` remain logical package boundaries inside those modules;
they are not separate Gradle modules. The Rust transport implementation lives
inside `crypto-core/native`.

Implemented source paths include:

- an Android Keystore wrapping-key manager, authenticated encrypted record
  store, encrypted owner/contact/pairing records, and revision-checked SQLite
  transactions;
- `SecureKeyboardRuntime`, which commits an advanced ratchet plus pending
  outbound ciphertext before publication and commits replay, advanced ratchet,
  and encrypted pending-display plaintext before returning it to the viewer;
- an embedded Private mode panel above the keyboard keys, backed by a bounded
  process-local draft connection, with no-learning/clipboard-history gates,
  best-effort buffer clearing, contact/vault status, a local Compact/Russian-
  words/English-words presentation preference, ciphertext-only publication
  through the active IME, and an **Encrypt / Decrypt** mode selector;
- a Rust `CBW1` presentation codec that wraps already canonical, universally
  fragmented `CB1` parts as Base4096 dictionary tokens and auto-detects compact,
  Russian-word, and English-word input under fixed allocation limits;
- an embedded copied-ciphertext receive flow that reads one bounded clipboard
  item only after an explicit action, hides the ordinary keys, decrypts through
  a hostless already-unlocked backend, and draws plaintext on a non-selectable
  protected surface inside the IME;
- bounded selected-text and `ACTION_PROCESS_TEXT` parsing, authenticated vault
  unlock, a drawing-only protected viewer, timeout/background clearing, and
  secure reply by internal contact ID;
- an offline ZXing/CameraX QR codec and one-shot scanner controller joined to
  a non-exported `FLAG_SECURE` two-QR pairing activity and an Android
  coordinator that stages/consumes encrypted one-shot state for both roles;
  and
- a non-exported contact-details UI for fingerprint/Safety Number display,
  rename, reverify, session destruction, deletion, and explicit re-pairing.

Pending outbound records are contact-bound. A `READY` operation may be offered
once without another ratchet step. Before the external Binder call it is
durably changed to `COMMIT_UNCERTAIN`; this state is never automatically
retried because the host may have accepted text even when its acknowledgement
was lost. The handoff is bound to the pending operation, exact ciphertext,
original host package/UID, input field metadata, selection and exact
`InputBinding.connectionToken`. `LatinIME` performs the only permitted host
`commitText()` and completes the pending record after an accepted insertion.
Inbound recovery is bound to the digest of the complete ordered ciphertext.
The embedded surface acknowledges the pending display only after its first
allowed plaintext draw. An abandoned or render-timed-out pre-draw lease retains
the encrypted pending display for an exact retry, while an acknowledged and
closed lease deletes it under no-history policy.

The pairing/contact flow expires or cancels orphaned active operations in
bounded cleanup batches and blocks a changed remote identity until explicit
Safety Number verification. It has JVM state-machine coverage but no live
two-device, process-kill, camera-permission, rotation, or GrapheneOS evidence.
The provisional wire format and remaining protocol decisions are documented in
`CRYPTO_PROTOCOL.md`.

## 1. System Context

CipherBoard is one offline Android APK with two user-facing roles:

1. a HeliBoard-derived input method for ordinary Russian, English, emoji,
   symbols, and Unicode input; and
2. a secure one-to-one messaging tool whose plaintext is composed and viewed
   only inside CipherBoard.

The host application is an untrusted text transport. The IME may read selected
compact or word-presented ciphertext from it, explicitly read copied ciphertext
from the system clipboard, and write an exact, already persisted presentation
to the host. Compact presentation contains canonical `CB1` parts. Word
presentation is an unencrypted, reversible wrapper around those same parts; it
does not alter the authenticated message. The IME MUST NOT write secure-composer
plaintext, return decrypted text through `ACTION_PROCESS_TEXT`, or place
plaintext on the system clipboard.

The application has no backend and no runtime network capability. Pairing is a
physical, bidirectional QR ceremony. Message delivery, availability, ordering,
and metadata privacy remain properties of the chosen external transport, not
of CipherBoard.

## 2. Source and Module Layout

The v1 source is organized around these ownership boundaries. A Gradle module
is preferred where it does not destabilize the upstream IME; otherwise the
same boundary MUST be enforced as a package plus an API/friend test.

| Logical module | Responsibility | May depend on |
| --- | --- | --- |
| `app/` | Application wiring, manifest, launcher/settings shell, receivers, dependency injection, branding | all Android-facing modules, not secret internals |
| `keyboard/` | Existing HeliBoard IME, layouts, dictionaries, emoji, toolbar, `InputConnection` gateway | `secure-ui` facade and narrow transport commit API |
| `secure-ui/` | Onboarding, contacts UI, embedded Private panel, protected viewer, vault prompts, lifecycle wiping | pairing, storage, envelope, crypto facades |
| `crypto-core/` | Rust `vodozemac` wrapper, identity/account/session operations, zeroization, JNI error mapping | `vodozemac`; no Android UI or database |
| `secure-storage/` | Keystore wrapping key, in-memory DEK lease, encrypted records, transactions, recovery | Android Keystore/SQLite and opaque crypto state |
| `pairing/` | Offer/response state machine, signatures, expiry/single-use checks, transcript, verification status | crypto, storage, QR codec facade |
| `transport-envelope/` | Canonical CBOR, universal `CB1` fragmentation/reassembly, compact and `CBW1` Base4096 presentations, limits, routing metadata | no UI, Keystore, database, or `InputConnection` |

The dependency direction MUST keep Android framework objects out of Rust and
must keep `InputConnection`, clipboard, intents, and logs out of `crypto-core`.
No module may invent a cryptographic primitive. `crypto-core` exposes a small
byte-oriented JNI API; no long-lived native pointer is owned by Kotlin.

Current upstream is HeliBoard `v4.0` at
`bd48798b99cccc99704eebf2a9259c02dbd684d5`. The physical Gradle/library
modules do not by themselves mean the logical boundaries above are complete.

## 3. Runtime Components and Export Rules

- `LatinIME` is exported only because Android requires an IME service and is
  protected by `android.permission.BIND_INPUT_METHOD`.
- `CipherBoardHomeActivity` is exported for `MAIN/LAUNCHER`. Inherited settings
  activities are non-exported; the external dictionary-dispatch intent surface
  is removed. Remaining content-URI import paths are bounded and still require
  final hostile-provider/device tests.
- The process-text activity is exported for `ACTION_PROCESS_TEXT`, accepts
  read-only `text/plain`, requires an explicit Decrypt action before parsing or
  ratchet mutation, validates caller-supplied text before unbounded allocation
  or storage, never returns a result containing plaintext, and has no arbitrary
  deep-link route.
- Viewer, legacy secure-reply composer, pairing, contact-details, vault-settings
  and security-information activities are non-exported. The shield does not
  launch the legacy composer. Pairing repair navigation
  carries only a short-lived process-local token rather than a raw contact ID.
- Boot and screen-state receivers perform only lock/migration bookkeeping.
  They never open the secure database before user unlock.
- Providers are non-exported and MUST NOT expose secure storage. Upstream file
  import and clipboard providers require a separate path/URI review.
- There is no WebView, dynamic code loading, remote service, sync adapter,
  account authenticator, accessibility service, or network service.

All externally supplied intents, URIs, QR bytes, and selected text are hostile.
Parsing precedes contact lookup and uses the limits in `CRYPTO_PROTOCOL.md`.

## 4. Direct-Boot Separation

Android device-encrypted (DE) storage is readable before the first unlock after
boot. Credential-encrypted (CE) storage is not. Upstream HeliBoard currently
uses `defaultToDeviceProtectedStorage`; CipherBoard MUST NOT allow that default
to place vault data in DE storage.

The final manifest removes `android:defaultToDeviceProtectedStorage="true"`.
The design uses two explicit repositories:

### DE allowlist

Only non-secret data required to render a basic keyboard before unlock may be
stored through an explicit device-protected context: schema/migration marker,
enabled built-in layouts, selected theme, keyboard geometry, and similarly
non-secret IME preferences. Static dictionaries and layouts remain packaged in
the APK. Secure plaintext, identities, contact names, fingerprints, QR state,
session state, replay state, pending operations, custom diagnostics, clipboard
history, and words entered in the Private panel are forbidden in DE storage.

### CE vault

Every secure record lives under an explicitly credential-protected context.
Opening it requires both `UserManager.isUserUnlocked == true` and an active
authenticated DEK lease. The IME and secure components are not direct-boot
aware, so they do not start against CE preferences before first unlock. After
first unlock, ordinary keyboard input is available; identity, pairing,
encrypt/decrypt, contact enumeration and pending recovery still require an
authenticated vault lease.

Tests scan both `/data/user_de/` and `/data/user/` on a test device using
sentinel values. Backup/restore code MUST have no route from the secure
repository into upstream keyboard backup archives.

## 5. Vault and Storage

### 5.1 Key hierarchy

1. Generate a non-exportable AES-256-GCM key in Android Keystore.
2. Request StrongBox first. Catch `StrongBoxUnavailableException` and retry with
   the platform Keystore without crashing; call the fallback TEE-backed only
   when `KeyInfo` actually reports `TRUSTED_ENVIRONMENT`.
3. Require `BIOMETRIC_STRONG` or `DEVICE_CREDENTIAL` authentication. The
   default lease is one minute; available policies are immediate, 30 seconds,
   one minute, and five minutes.
4. Generate a random 256-bit data-encryption key (DEK). Wrap it with the
   Keystore key using a fresh 96-bit nonce and fixed, versioned AAD.
5. Keep the unwrapped DEK only in a short-lived, process-local byte buffer. No
   master key or DEK is written to preferences, assets, source, logs, or JNI
   strings.

`KeyInfo.securityLevel` (or `isInsideSecureHardware` on older supported APIs)
is returned and shown after unlock. The StrongBox attempt falls back only to a
key reported as `TRUSTED_ENVIRONMENT`; software or unknown security levels are
rejected rather than mislabeled or silently accepted. Keystore invalidation
locks the vault and existing records are not silently replaced. Physical
StrongBox, TEE-fallback, biometric/device-credential and invalidation evidence
is still required.

### 5.2 Record encryption

SQLite provides transactions, indexes over random internal IDs, and crash
recovery; it is not treated as encryption. Each logical value is independently
encrypted with AES-256-GCM under the DEK and a fresh random 96-bit nonce. AAD
contains at least application/schema version, record type, random record ID,
contact ID where applicable, and monotonic record revision. Nonces are stored
beside ciphertext and uniqueness is tested.

Encrypted records include owner identity/account pickle, local owner name,
contacts and local names, pairing states, session pickles, routing data, replay
ledger, pending sends, and pending displays. Vodozemac pickles receive this
outer authenticated-encryption layer; their legacy pickle encryption is not
the sole at-rest protection.

The current SQLite schema also keeps operational indexes outside those AEAD
blobs: record kind, SHA-256-derived keys/owner keys, record revision and
creation/update timestamps, plus a `replay_ids` table containing a hash derived
from random internal contact ID and public message ID and a receive timestamp.
The bounded seen-message-ID ledger itself is also inside the encrypted session
snapshot. The unencrypted indexes do not reveal contact names or raw IDs, but
they reveal counts/timing and are not independently authenticated; database
tampering can cause denial of service. Minimizing or authenticating this
metadata is an open storage-hardening item.

The database uses one SQLite transaction for every ratchet mutation.
`SecureKeyboardRuntime` currently serializes operations with one process-wide
lock and the store checks a persisted expected revision. An optimistic revision
mismatch aborts without publishing output. Android backup is disabled in the
source manifest and extraction rules exclude all app data; the merged release
APK and real backup/transfer behavior still require verification. There is no
ratchet backup, export, restore, or clone function.

Flash wear levelling and JVM copies prevent a guarantee of physical secure
erasure. Deletion removes keys/references and overwrites mutable buffers on a
best-effort basis; documentation MUST not claim more.

## 6. IME Plaintext Isolation

The shield toggles an embedded Private mode panel inside CipherBoard's IME
window. It does not launch the composer activity. While active, software-key
events and IME text-edit commands are routed to a bounded local
`EmbeddedSecureInputConnection`, not to the host application's connection. The
panel displays the draft above the ordinary keys, contact/Vault state, selected
message-format estimate and explicit Encrypt/Clear/Close actions. The output
format is selected separately under **Home > Message format**; there is no SMS
or transport selector in the panel. No plaintext intent extra, saved-state
field or persistent draft API exists.

The interactive draft is capped at 32,768 UTF-16 code units to bound UI work
and wiping latency. UTF-8 encoding additionally applies the selected
presentation limit before encryption: 192 KiB in Compact and 32 KiB in either
word format. The lower word limit ensures that the complete first/pre-key Olm
message fits the bounded 48-KiB word wrapper.

After an accepted ciphertext insertion, the plaintext remains in the panel so
the sender can verify what was sent. It is wiped on explicit clear or close,
host-field/token change, screen lock, IME destruction or the relevant secure
lifecycle transition. Mutable buffers and UI text are cleared best effort;
Android rendering, Binder and JVM copies prevent a complete RAM-erasure claim.

### 6.1 CipherBoard-owned editor boundary

`LatinIME`, `InputLogic`, `RichInputConnection`, gesture callbacks and toolbar
edit commands select the local draft connection while Private mode is active.
Private-mode `EditorInfo` forces `IME_FLAG_NO_PERSONALIZED_LEARNING` and
no-suggestion semantics; user-dictionary writes, emoji recents, personalized
history, clipboard history, paste and plaintext clipboard fallbacks are
disabled. The IME window sets `FLAG_SECURE`. Password fields require an
explicit warning before activation.

The scope stores the exact non-null `InputBinding.connectionToken` as well as
package/UID and editor metadata. Any field or token change closes the panel and
wipes the draft and embedded plaintext. The Vault-unlock activity is
non-exported and may cause Android to recreate the connection; one explicit,
metadata-matching token rebind is allowed only after its one-shot process-local
handoff reports a successful unlock.

Android physical-keyboard dispatch is outside this software-key routing
boundary and may deliver characters directly to the focused host view. Private
drafts therefore MUST be entered with CipherBoard's on-screen keys; hardware
keyboard use is unsupported and warned against.

### 6.2 One-shot host commit gate

Encryption obtains the exact contact-bound `PendingOutbound` created in the
same revision-checked storage operation. `SecureImeBridge` receives a one-shot
process-local claim containing its operation ID and the exact transport text
deterministically reconstructed from the persisted canonical parts and
versioned presentation enum. The claim is scoped to the active embedded host
scope, including the exact connection token. The runtime always produces canonical `CB1` parts with the universal
16-KiB core fragmentation profile, then applies the sender's local presentation
preference. The receiver does not need the same preference because decode is
auto-detected.

After revalidating that scope, the bridge atomically marks the durable record
`COMMIT_UNCERTAIN` and only then invokes the host `commitText()` once with the
stored ciphertext. On accepted insertion it deletes the pending record. A false
return, exception or process death after the state transition leaves an
explicit uncertain record: it is shown as delivery-unknown and MUST NOT be
automatically retried. The draft stays visible after success; clearing it is a
separate explicit/lifecycle operation and is never part of publication.

### 6.3 Embedded copied-ciphertext receive gate

The common receive flow is explicit: the user copies a complete compact or word
message, opens the shield panel, selects **Decrypt**, and presses **Paste and
decrypt**. The controller reads exactly one clipboard text item with the
existing allocation bounds, auto-detects compact/Russian/English presentation,
recovers and validates the complete canonical `CB1` part set before Vault
access, and does not change the clipboard. Clipboard content is ciphertext; no
plaintext clipboard API exists. The ordinary keyboard wrapper and suggestion
strip are hidden in Decrypt mode, so software keys cannot look like an input
path for the read-only message.

Word decode is bounded at a 48-KiB decoded wrapper, 32,768 dictionary tokens,
and the Android 384-Ki UTF-16 input boundary. A tag-first truncated SHA-256
checksum detects accidental transport edits before reconstruction, but it is
not an authenticator and is not trusted for message integrity; Olm/AEAD remains
the authentication boundary. A word list setting affects future sends only and
is neither stored per contact nor negotiated with the peer. Both peers require
CipherBoard 0.4 or newer for word presentation. Compact presentation remains
interoperable with earlier releases, and decode retains legacy SMS-fragmented
`CB1` compatibility.

Envelope parsing runs off the main thread. If authentication is required, the
controller keeps only ciphertext and an opaque parsed handle in process memory.
It creates a random one-shot `EmbeddedVaultUnlockBridge` token and sends only
that token to the non-exported `SecureVaultUnlockActivity`; ciphertext and
plaintext are never Intent extras. The activity must activate the token once
and complete it once. Cancellation, duplicate activation, timeout, screen-off,
or a failed/mismatched host-scope return invalidates the handoff and closes the
panel. Only then may the exact editor metadata obtain its single authorised
connection-token rebind. `decryptUnlocked()` never presents authentication UI
and fails closed if the Vault expired between the handoff and worker execution.
Parser and decrypt completions cross to the main thread through an owned-result
handoff. Cancellation invalidates its generation and closes queued or late
results before callbacks are removed, so a lifecycle race cannot orphan a
plaintext owner in the main looper queue.

After the atomic receive commit, plaintext is decoded into `WipeableText` and
owned by `SecurePlaintextView`, a drawing-only view with no focus, selection,
long-click action mode, saved state, Accessibility text, autofill, or content
capture. Before the first draw, the controller rechecks that the secure IME and
Vault are still active. Only an allowed completed draw calls
`SecureDisplayLease.markDisplayed()` and starts the viewer timeout. A bounded
render timeout clears the surface without marking the lease, retaining the
encrypted pending display for exact recovery. **Reply securely** clears this
surface, wipes any pre-existing outbound draft, resolves the opaque reply
capability against local contacts, switches to Encrypt mode, and selects the
same local contact without an Intent.

The panel uses compact landscape and constrained-height/large-font dimensions.
The received message lives in a bounded-height scroll view; summary/status text
uses bounded lines and commands retain minimum touch targets. This reduces
clipping risk but does not replace screenshot QA in portrait/landscape at font
scales through 2.0 in both supported locales.

## 7. Atomic Ratchet Operations

The database commit is the publication boundary. JNI state-changing calls
return an indivisible result object containing the next sealed state plus
output bytes; Kotlin MUST not publish the output first.

### 7.1 Send

The store represents publication with a contact-bound encrypted
pending-outbound record whose delivery state is `READY` or
`COMMIT_UNCERTAIN`. The inner message has no sender sequence; the persisted
ratchet revision supplies local concurrency control.

1. Lock the contact and load session revision `n`.
2. Encode the inner payload and call `Session::encrypt()` once.
3. Build and fragment the exact canonical `CB1` wire representation with the
   universal profile, then apply the selected compact or word presentation.
4. In one database transaction, store session revision `n+1` and an encrypted
   pending record containing contact ID, canonical `CB1` parts, and the
   versioned presentation enum.
5. Only after commit and exact connection-token validation, claim the `READY`
   operation once.
6. Atomically change it to `COMMIT_UNCERTAIN` before crossing the host Binder
   boundary.
7. Verify deterministic reconstruction against the persisted pending bytes,
   then call `InputConnection.commitText()` once with that exact text.
8. If it returns true, delete the pending record. On a false return, exception,
   process death or acknowledgement loss, retain `COMMIT_UNCERTAIN` and do not
   retry automatically.

A crash before step 4 leaves revision `n` and no externally visible
ciphertext. A crash after step 4 but before step 6 leaves `READY`, which can be
claimed once without another encryption step. From step 6 onward, delivery is
inherently ambiguous because Android provides no transactional acknowledgement
across application processes. The durable `COMMIT_UNCERTAIN` state prevents an
automatic duplicate; the user must inspect the host transport before deciding
what to do. Receiver replay protection still rejects delivery of the same
ciphertext twice, but cannot remove duplicated transport text.

### 7.2 Receive

The store represents readiness by one encrypted pending-display record. It is
bound to the contact, message ID and SHA-256 digest of the exact complete
ordered ciphertext parts.

The provisional inner message binds message ID and capabilities inside Olm but
does not repeat identity, routing tag, sequence or content type. Strict UTF-8
validation happens in the Android viewer after the receive transaction, not in
Rust. The richer validation in step 3 remains a target protocol requirement.

1. Strictly parse/reassemble all parts, then lock and resolve the contact.
2. Reject a committed message ID replay before invoking Rust.
3. Decrypt to a temporary mutable buffer and validate the authenticated inner
   identity, routing tag, message ID, sequence, content type, and UTF-8.
4. In one transaction, store session revision `n+1`, replay record, receive
   sequence/window, and a DEK-encrypted `READY_TO_DISPLAY` plaintext record.
5. Only after commit, decrypt the pending display record into a secure viewer.
6. Transfer plaintext to a drawing-only protected view without yet consuming
   the display lease.
7. Mark the lease displayed only after the first allowed draw. On close,
   background, timeout, mode switch, or reply after that draw, wipe UI buffers
   and delete the pending display because v1 has no plaintext history. Abandon
   or render timeout before the draw wipes the temporary buffer but retains the
   encrypted record for exact retry.

A crash before step 4 changes nothing and the ciphertext may be tried again. A
crash after step 4 leaves a recoverable encrypted pending display without
decrypting the Olm message again. Retrying the exact ciphertext reopens that
record; a same-ID payload with a different digest fails closed.
Authentication, parse, wrong-contact, replay, or skipped-key errors are designed
not to change persisted state. A targeted remote-process SIGKILL after the
inbound commit verifies recovery of the advanced revision, replay marker and
encrypted pending display. Crashes between individual transaction statements
and the wider device restart/error matrix remain untested.

## 8. Pairing and Trust

The target pairing state machine is `OFFER_CREATED`, `RESPONSE_CREATED`,
`RESPONSE_ACCEPTED`, `UNVERIFIED`, `VERIFIED`, `EXPIRED`, or `CANCELLED`.
Offers must have a short maximum lifetime, random ID and nonce, encrypted
pending storage, and single-use/import protection. Expiry supplements rather
than replaces a consumption ledger because offline wall-clock rollback cannot
be excluded. The provisional Rust implementation permits up to 15 minutes;
the earlier ten-minute design value is not its current wire behavior.

Device B verifies and imports A's signed offer, creates an Olm V2 outbound
session, encrypts a pairing-confirmation pre-key message, and shows a signed
response QR. Device A verifies the response and transcript, creates the inbound
session, consumes the one-time key, and commits the advanced account pickle,
session, offer consumption, and contact state atomically. Ordinary `CB1` user
messages can never create an inbound session. Both derive the same safety hash
and comparison values as specified in `CRYPTO_PROTOCOL.md`.

Each user must visually compare the displayed values and explicitly confirm
before that device persists a `VERIFIED` local contact. A changed identity key
is a critical `KEY_CHANGED` state; no trust-on-first-use replacement is
allowed. The current repair UI requires explicit session destruction first,
then permits replacement only for a contact already marked as requiring
pairing. Cancelling that new ceremony therefore leaves the contact safely
blocked but without its old session.

Crypto-core offer/response generation, storage codecs/repository mutations,
Android coordinator and two-QR activity are joined in the current source. The
coordinator atomically stages the responder session/response, resumes only the
same pending offer, rejects consumed/expired state, and consumes pending state
with contact and initial ratchet creation after explicit local confirmation.
The activity requests Camera only from a Scan action, keeps QR handles out of
saved state, clears QR bitmaps on exit/background, and is non-exported with
`FLAG_SECURE`. Entry performs bounded cleanup of expired/orphaned active
pairings, cancelling them and tombstoning their session payload; unfinished
pairings can also be deleted explicitly. A changed identity is persisted as a
blocking `KEY_CHANGED`/repair-required state until explicit physical pairing
and Safety Number confirmation. The numeric Safety Number and eight-word code
are both deterministic renderings of the same transcript hash. JVM tests cover
these state transitions; live two-device and forced-process-crash evidence is
still absent.

## 9. Secure UI Lifecycle

The IME window sets `FLAG_SECURE` while the embedded Private panel is active;
the panel is not a separate task or activity and therefore has no recent-app
entry. Embedded Decrypt mode hides the ordinary keys and uses the same
drawing-only plaintext class as the separate viewer. It clears on panel close,
mode change, host-scope loss, screen off, Vault expiry, explicit hide, render
failure, or configured timeout. Its reply capability is resolved locally and
does not launch a plaintext-bearing Activity.

The process-text/viewer activity remains protected and excluded from recents by
the source manifest. Both viewers disable autofill/content capture; the
activity also disables Android 13+ recents screenshots, clears on
pause/stop/UI-hidden even while parse/decrypt work is in flight, and uses the
same timeout preference bounded to 10 seconds through five minutes. Immediately
before first draw it reapplies the Vault timeout policy and fails closed if the
Vault locked. Plaintext is drawn by a non-focusable, non-selectable view
excluded from Accessibility; Assistant bundles are cleared. Screen-off,
screenshot, recents, Assistant and Accessibility behavior still requires
device evidence.

Kotlin uses `ByteArray`/`CharArray` where APIs permit, wipes arrays in `finally`,
cancels work at lifecycle exit, and clears editable/spannable and IME caches.
Android `EditText`, Binder, JNI, GC, and rendering may make copies, so complete
RAM zeroization is not promised. Logs contain only fixed error codes and random
operation IDs; release logging has no content-bearing path.

## 10. No-Network Invariant

The merged manifest for every distributable variant MUST contain none of:
`INTERNET`, `ACCESS_NETWORK_STATE`, SMS, Contacts, package-wide query,
overlay, or accessibility permissions. Camera is requested only after the user
presses Scan QR. `allowBackup=false`, restrictive data-extraction rules, and
cleartext traffic denial are mandatory defense in depth.

Build and release gates also verify:

- no Firebase, Google Play services, analytics, crash reporting, ads, HTTP
  client, WebView, localhost access, remote configuration, or dynamic loader;
- the pinned offline QR decoder contains no Play Services/cloud path;
- all dictionaries, codebooks, models, and configuration are APK resources;
- `aapt`, `apkanalyzer`, and source/dependency scans agree on permissions; and
- GrapheneOS Network permission is disabled during device acceptance even
  though the APK itself lacks Android network permissions.

Any appearance of `android.permission.INTERNET` is an unconditional release
failure.

The current source manifest contains no `INTERNET` or `ACCESS_NETWORK_STATE`.
The CameraX video/media dependency path that introduced network-state
permission is excluded from the runtime graph. The manifest also has
`allowBackup=false`, complete extraction exclusions, and cleartext denial.
These source controls and policy tests are implemented. A pre-public local
signed candidate passed the scripted APK permission and signature policy, but
its evidence bundle is untracked and unpublished. The final public tag must be
rebuilt, independently dumped, and accompanied by its own `BUILD_INFO.txt` and
release assets rather than inheriting that candidate's result.

## 11. Architectural Limits

This design cannot hide external-transport metadata or guarantee delivery. It
cannot protect plaintext already visible on a fully compromised unlocked
device, from malicious Accessibility/system software, a camera, shoulder
surfing, coercion, or a maliciously rebuilt APK. `FLAG_SECURE` and memory wipes
are defense in depth, not absolute controls. SQLite transactions prevent normal
crash rollback; they do not provide a hardware monotonic counter against a
privileged attacker restoring an old filesystem image. The complete limitation
set is maintained in `THREAT_MODEL.md`.
