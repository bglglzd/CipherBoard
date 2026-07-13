# CipherBoard Architecture

Status: normative design for CipherBoard v1. Statements marked **MUST** are
release requirements, not claims about the current worktree. Implementation
status is tracked separately in `SECURITY_CHECKLIST.md`.

## 1. System Context

CipherBoard is one offline Android APK with two user-facing roles:

1. a HeliBoard-derived input method for ordinary Russian, English, emoji,
   symbols, and Unicode input; and
2. a secure one-to-one messaging tool whose plaintext is composed and viewed
   only inside CipherBoard.

The host application is an untrusted text transport. The IME may read selected
`CB1` ciphertext from it and may write an exact, already persisted `CB1`
ciphertext to it. It MUST NOT write secure-composer plaintext, return decrypted
text through `ACTION_PROCESS_TEXT`, or place plaintext on the system clipboard.

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
| `secure-ui/` | Onboarding, contacts UI, secure composer/viewer, vault prompts, lifecycle wiping | pairing, storage, envelope, crypto facades |
| `crypto-core/` | Rust `vodozemac` wrapper, identity/account/session operations, zeroization, JNI error mapping | `vodozemac`; no Android UI or database |
| `secure-storage/` | Keystore wrapping key, in-memory DEK lease, encrypted records, transactions, recovery | Android Keystore/SQLite and opaque crypto state |
| `pairing/` | Offer/response state machine, signatures, expiry/single-use checks, transcript, verification status | crypto, storage, QR codec facade |
| `transport-envelope/` | Canonical CBOR, `CB1` Base64url, fragmentation/reassembly, limits, routing metadata | no UI, Keystore, database, or `InputConnection` |

The dependency direction MUST keep Android framework objects out of Rust and
must keep `InputConnection`, clipboard, intents, and logs out of `crypto-core`.
No module may invent a cryptographic primitive. `crypto-core` exposes a small
byte-oriented JNI API; no long-lived native pointer is owned by Kotlin.

Current upstream is HeliBoard `v4.0` at
`bd48798b99cccc99704eebf2a9259c02dbd684d5`. The existing physical `:app`
module and `crypto-core/native` scaffold do not by themselves mean the logical
boundaries above are complete.

## 3. Runtime Components and Export Rules

- `LatinIME` is exported only because Android requires an IME service and is
  protected by `android.permission.BIND_INPUT_METHOD`.
- The launcher/settings activity is exported only for `MAIN/LAUNCHER`.
- The process-text activity is exported for `ACTION_PROCESS_TEXT`, accepts
  read-only `text/plain`, validates caller-supplied text before allocation or
  storage, never returns a result containing plaintext, and has no arbitrary
  deep-link route.
- Pairing, viewer, composer, contact, and vault activities are non-exported.
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
history, and learned secure-composer words are forbidden in DE storage.

### CE vault

Every secure record lives under an explicitly credential-protected context.
Opening it requires both `UserManager.isUserUnlocked == true` and an active
authenticated DEK lease. Before first unlock, the shield action shows a locked
state and cannot create identity, pair, encrypt, decrypt, enumerate contacts,
or recover a pending operation. The ordinary keyboard remains usable.

Tests scan both `/data/user_de/` and `/data/user/` on a test device using
sentinel values. Backup/restore code MUST have no route from the secure
repository into upstream keyboard backup archives.

## 5. Vault and Storage

### 5.1 Key hierarchy

1. Generate a non-exportable AES-256-GCM key in Android Keystore.
2. Request StrongBox first. Catch `StrongBoxUnavailableException` and retry in
   TEE without crashing.
3. Require `BIOMETRIC_STRONG` or `DEVICE_CREDENTIAL` authentication. The
   default lease is one minute; available policies are immediate, 30 seconds,
   one minute, and five minutes.
4. Generate a random 256-bit data-encryption key (DEK). Wrap it with the
   Keystore key using a fresh 96-bit nonce and fixed, versioned AAD.
5. Keep the unwrapped DEK only in a short-lived, process-local byte buffer. No
   master key or DEK is written to preferences, assets, source, logs, or JNI
   strings.

`KeyInfo.securityLevel` (or `isInsideSecureHardware` on older supported APIs)
is shown honestly as StrongBox, TEE, software, or unknown. Secure messaging
fails closed if a hardware-backed level required by release policy is not
available; the ordinary keyboard still works. Keystore invalidation locks the
vault and starts an explicit destructive recovery/re-pair flow. It never
silently creates a replacement identity for existing contacts.

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

The database uses foreign keys and one transaction connection for every
ratchet mutation. A per-contact mutex plus a persisted expected revision
serializes send and receive. An optimistic revision mismatch aborts without
publishing output. Android backup is disabled and data-extraction rules exclude
all app data. There is no ratchet backup, export, restore, or clone function.

Flash wear levelling and JVM copies prevent a guarantee of physical secure
erasure. Deletion removes keys/references and overwrites mutable buffers on a
best-effort basis; documentation MUST not claim more.

## 6. IME Plaintext Isolation

Secure Composer does not edit the host application's field. It owns a private
editor buffer in CipherBoard and uses the existing HeliBoard key layout as an
input surface. Plaintext is never passed in an intent extra, saved instance
state, `SavedStateHandle`, persistent draft, clipboard, suggestion history, or
host `InputConnection`.

### 6.1 First gate: event routing

`SecureModeController` has fail-closed states `OFF`, `ENTERING`, `ACTIVE`,
`ENCRYPTING`, and `EXITING`. In every state other than `OFF`, printable keys,
gesture results, suggestions, emoji, space/enter, delete, composing updates,
and editor actions are routed to a `SecureComposerSink`. The normal
`InputLogic` host sink is detached. Personal learning, recents updates,
clipboard suggestions/history, application completions, and host surrounding
text reads are disabled before the state becomes `ACTIVE`.

Entry first finishes any pre-existing ordinary host composition, clears
HeliBoard caches, and then flips the gate. Exit wipes composer buffers, clears
IME caches and suggestion state, and only then restores ordinary routing. A
password field requires an explicit warning before opening secure mode and
never triggers an automatic ciphertext commit.

### 6.2 Second gate: `RichInputConnection`

Event routing is not sufficient because upstream has many output paths.
`RichInputConnection` (and any remaining direct
`getCurrentInputConnection()` call) MUST enforce the same gate at the final IPC
boundary. While secure mode is not `OFF`, it denies normal calls that can send
or transform content, including:

- `commitText`, `setComposingText`, `setComposingRegion`, `commitCompletion`,
  `commitCorrection`, and `commitContent`;
- printable `sendKeyEvent`, paste/private commands, and editor actions;
- host selection/cursor edits or batch operations not needed by the one
  authorized commit; and
- surrounding/extracted-text reads except the explicit bounded
  "decrypt selected ciphertext" operation.

Encryption creates a one-use, in-memory `CiphertextCommitCapability` bound to
the persisted pending-operation ID, target `InputConnection` generation, exact
wire bytes, and expiry. A dedicated `CiphertextCommitter` re-parses those bytes
as bounded `CB1` data, verifies they equal the encrypted pending record, and
calls `InputConnection.commitText()` once. The capability cannot authorize
arbitrary text, `setComposingText`, key events, content URIs, or a different
editor generation. It is consumed on the attempt, regardless of result.

A CI source scan maintains an allowlist of all direct `InputConnection` access.
Tests use a recording hostile `InputConnection` and fail if any secure
plaintext reaches any method, not only `commitText`.

## 7. Atomic Ratchet Operations

The database commit is the publication boundary. JNI state-changing calls
return an indivisible result object containing the next sealed state plus
output bytes; Kotlin MUST not publish the output first.

### 7.1 Send

Persisted send states are `READY_TO_COMMIT`, `HOST_ACCEPTED`, and `ABANDONED`.

1. Lock the contact and load session revision `n`.
2. Encode the inner payload and call `Session::encrypt()` once.
3. Build and fragment the exact `CB1` wire representation.
4. In one database transaction, store session revision `n+1`, sender sequence,
   and an encrypted `READY_TO_COMMIT` record containing the exact ciphertext.
5. Only after commit, mint the scoped commit capability and send the exact wire
   bytes to the current host editor.
6. If `InputConnection.commitText()` returns true, mark `HOST_ACCEPTED` in a
   second transaction and wipe the composer. On false, retain the pending
   ciphertext and show a retry/export-ciphertext-only action.

A crash before step 4 leaves revision `n` and no externally visible
ciphertext. A crash after step 4 recovers the already encrypted bytes and MUST
never call `encrypt()` again. A crash after the host accepted text but before
step 6 is inherently ambiguous because Android provides no transactional
acknowledgement across application processes. Recovery labels the operation
"insertion status unknown"; only an explicit user retry may reinsert the same
ciphertext. It never advances the ratchet again. Receiver replay protection
makes such a duplicate harmless, though duplicate transport text can remain.

### 7.2 Receive

Persisted display states are `READY_TO_DISPLAY`, `DISPLAYING`, and `CLOSED`.

1. Strictly parse/reassemble all parts, then lock and resolve the contact.
2. Reject a committed message ID replay before invoking Rust.
3. Decrypt to a temporary mutable buffer and validate the authenticated inner
   identity, routing tag, message ID, sequence, content type, and UTF-8.
4. In one transaction, store session revision `n+1`, replay record, receive
   sequence/window, and a DEK-encrypted `READY_TO_DISPLAY` plaintext record.
5. Only after commit, decrypt the pending display record into the secure viewer.
6. On close/background/timeout, wipe UI buffers and delete the pending display
   record because v1 has no plaintext history.

A crash before step 4 changes nothing and the ciphertext may be tried again. A
crash after step 4 recovers the pending display without decrypting the Olm
message again. Authentication, parse, wrong-contact, replay, or skipped-key
errors do not change persisted session state.

## 8. Pairing and Trust

Pairing is an explicit state machine: `OFFER_CREATED`, `RESPONSE_CREATED`,
`RESPONSE_ACCEPTED`, `UNVERIFIED`, `VERIFIED`, `EXPIRED`, or `CANCELLED`.
Offers have a ten-minute maximum lifetime, random ID and nonce, are stored
encrypted, and are single-use. Imported pairing IDs are recorded to reject
re-import. Expiry supplements rather than replaces the consumption ledger,
because offline wall-clock rollback cannot be excluded.

Device B verifies and imports A's signed offer, creates an Olm V2 outbound
session, encrypts a pairing-confirmation pre-key message, and shows a signed
response QR. Device A verifies the response and transcript, creates the inbound
session, consumes the one-time key, and commits the advanced account pickle,
session, offer consumption, and contact state atomically. Ordinary `CB1` user
messages can never create an inbound session. Both derive the same transcript
hash, numeric Safety Number, and emoji code as specified in
`CRYPTO_PROTOCOL.md`.

Cryptographic session creation yields `UNVERIFIED`. Each user must visually
compare the displayed values and explicitly confirm before that local contact
becomes `VERIFIED`. A changed identity key is a critical `KEY_CHANGED` state;
no trust-on-first-use replacement is allowed. Re-pairing destroys the old
session only after explicit confirmation and a new physical ceremony.

## 9. Secure UI Lifecycle

Composer and viewer windows set `FLAG_SECURE`, disable autofill/content capture,
exclude themselves from recents, hide on screen-off, and clear on
`onStop`/background. Viewer text is non-selectable by default, has no share or
copy action, is not exposed to Assistant, and closes on the configured timeout.
"Reply securely" carries only an internal random contact ID; plaintext is
wiped before navigation.

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

## 11. Architectural Limits

This design cannot hide external-transport metadata or guarantee delivery. It
cannot protect plaintext already visible on a fully compromised unlocked
device, from malicious Accessibility/system software, a camera, shoulder
surfing, coercion, or a maliciously rebuilt APK. `FLAG_SECURE` and memory wipes
are defense in depth, not absolute controls. SQLite transactions prevent normal
crash rollback; they do not provide a hardware monotonic counter against a
privileged attacker restoring an old filesystem image. The complete limitation
set is maintained in `THREAT_MODEL.md`.
