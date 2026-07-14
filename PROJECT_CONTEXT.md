# CipherBoard Project Context

## Product

CipherBoard is an unofficial, modified HeliBoard keyboard for one-to-one
offline encrypted text exchange, primarily on current GrapheneOS devices. Two
people install the same APK, create local cryptographic identities, pair in
person by scanning each other's QR codes, compare a Safety Number, and carry
compact `CB1` or reversibly word-presented ciphertext through any ordinary text
application.

The external application is an untrusted transport. Secure-composer plaintext
must never enter its editor; decrypted plaintext is shown only in a protected
CipherBoard window. There is no account, phone number, email address, username,
server, push channel, analytics service, or runtime download.

Working identifiers are:

| Item | Value |
| --- | --- |
| Product name | `CipherBoard` |
| Application ID | `org.cipherboard.securekeyboard` |
| Native crate | `cipherboard-crypto` |
| Canonical wire prefix | `CB1:` |
| Word presentation | `CBW1`, Russian or English Base4096 |

The product name, application ID/namespace-derived authorities, version, and
artifact base name MUST be defined from centralized build configuration. The
current upstream `helium314.keyboard` identifiers and HeliBoard artifact name
are baseline values to migrate, not final CipherBoard values.

The APK minimum is API 23 for ordinary keyboard use. Version 1
secure messaging requires API 30 or newer so the Keystore key can enforce the
combined `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` policy without a weaker
compatibility path. On older Android the secure entry points fail closed and
the ordinary keyboard remains available. Current supported GrapheneOS devices
meet this floor.

## Repository Baseline

- Workspace: repository root
- Default public branch: `main`
- Official upstream: `HeliBorg/HeliBoard`
- Stable tag: `v4.0`
- Pinned upstream commit: `bd48798b99cccc99704eebf2a9259c02dbd684d5`
- Upstream license: GPL-3.0, with inherited Apache-2.0 and CC BY-SA 4.0
  material documented separately
- Android baseline: compile/target SDK 36, Java/JVM 17, NDK
  `28.0.13004108`
- Crypto decision: `matrix-org/vodozemac` `0.10.0`, exact crate checksum and
  commit recorded in `docs/adr/0001-crypto-library.md`

CipherBoard is not an official HeliBoard release and must use distinct naming,
iconography, signing, and support language. Russian and English layouts,
dictionaries, emoji, symbols, Unicode support, and ordinary HeliBoard settings
remain functional.

The repository now contains the HeliBoard-based `:app` together with dedicated
`:crypto-core`, `:pairing`, and `:secure-storage` modules. Release gates inspect
the packaged manifest, DEX files, native ABIs, signature, backup policy, and
runtime permissions. Passing those automated checks is not a substitute for an
independent Android and applied-cryptography audit.

## Non-Negotiable Invariants

1. **No network capability.** No `INTERNET`, `ACCESS_NETWORK_STATE`, Google Play
   services, Firebase, HTTP client, localhost call, remote config, telemetry,
   advertising, crash reporter, or runtime model/dictionary download.
2. **Plaintext stays inside CipherBoard.** Secure plaintext is never committed
   to a host editor, copied to clipboard, logged, put in an intent, saved as UI
   state, notified, shared, backed up, or retained as history by default.
3. **Ratchet before publication.** Advanced session state and the exact pending
   ciphertext are committed atomically before any `InputConnection` write.
   Receive state, replay record, and encrypted pending display are committed
   atomically before plaintext is shown.
4. **No custom cryptography.** Olm/Double Ratchet and primitive operations come
   from pinned, reviewed libraries/platform APIs. CipherBoard defines only
   bounded formats, state machines, key management, and UI integration.
5. **Physical pairing.** Version 1 has no remote pairing or key directory.
   Trust becomes Verified only after reciprocal QR flow and explicit visual
   comparison. Identity changes fail closed and require re-pairing.
6. **Vault is not merely app-private storage.** Identity, session, contact,
   pairing, replay, and pending data are AEAD-encrypted under a random DEK
   wrapped by an authenticated hardware-backed Android Keystore key.
7. **No secret backup/restore.** `allowBackup=false`; data extraction, upstream
   backup, and root-oriented export paths exclude the vault and ratchet state.
8. **Honest claims.** The product does not claim absolute security or an
   independent audit. Platform and memory-erasure limits are visible to users.
9. **Presentation is not cryptography.** Russian/English words wrap the same
   authenticated canonical `CB1` parts. Their checksum is not authentication,
   and the UI must call the result camouflage rather than steganography or
   natural language.

## Target Users and Core Flows

The main user is a person who wants message content hidden from an SMS operator
or external messenger service without depending on another online identity.
The interface uses ordinary language and calm Material styling; cryptographic
details remain available for verification rather than dominating routine use.

### First run

After the first credential unlock, the user authenticates to create a local
vodozemac identity and optionally enters a device-local display name. No
personal identifier is requested. CipherBoard displays the public identity
fingerprint and explains that clearing app data or losing signing/vault state
requires re-pairing.

### Pairing

Device A creates a ten-minute, single-use signed offer QR. Device B scans it,
assigns any local contact name, creates an outbound Olm V2 session, and displays
a signed response QR. Device A scans the response and atomically creates the
inbound session. Both compare the derived numeric and emoji representations and
confirm locally. Names remain local and are excluded from the transcript.

### Send

The user opens the shield tool, authenticates, selects a verified contact, and
types into CipherBoard's private composer using the standard layouts. Encrypt
atomically advances the session, always builds universally fragmented canonical
`CB1` parts, and persists their exact compact/Russian-word/English-word
presentation. Only that ciphertext is committed to the host editor after an
explicit user action. Presentation is a sender-local setting, not a contact or
session capability.

### Receive

The user copies a complete compact or word-presented message, opens Decrypt in
the shield panel, and explicitly asks CipherBoard to paste and decrypt it.
`ACTION_PROCESS_TEXT` and selected text remain alternatives. CipherBoard 0.4+
auto-detects all three presentations, recovers and strictly validates canonical
`CB1` parts, then authenticates and advances the receive state before showing
plaintext in a `FLAG_SECURE` surface. It never replaces the selection or returns
plaintext to the caller. Clipboard input and fallback accept ciphertext only.

## Version 1 Scope

Included:

- ordinary HeliBoard IME behavior with Russian, English, emoji, symbols, and
  user-configurable keyboard appearance;
- local identity, contact vault, rename/delete/reset/re-pair operations;
- reciprocal offline QR pairing and explicit Safety Number verification;
- one-to-one Olm V2 sessions, replay tracking, bounded out-of-order handling;
- canonical, versioned `CB1` envelopes, universal fragmentation for new sends,
  backward parsing of legacy SMS-profile parts, and compact/Russian/English
  presentation;
- secure composer, selected-ciphertext decrypt, protected viewer and reply;
- StrongBox-first/TEE-fallback vault with configurable lock lease;
- English and Russian product UI, accessibility for non-secret controls, light,
  dark, landscape, large text, RTL-safe layout, and optional dynamic color;
- reproducible build metadata, SBOM, signed APK verification, permission and
  dependency blockers.

Not included:

- groups or Megolm;
- server discovery, registration, remote key lookup, backup, sync, or recovery;
- remote pairing through an untrusted messenger;
- attachment, voice, image, location, contact, or notification encryption;
- plaintext message history or export;
- hiding message timing, recipient relationships, size, or transport account
  metadata;
- guaranteed protection on a compromised unlocked OS, from Accessibility,
  cameras, observers, coercion, or a malicious APK;
- independent security audit certification.

## Architectural Vocabulary

- **Identity:** vodozemac account identity keys generated locally. The owner's
  local display name is not identity material.
- **Contact:** a random local ID plus locally chosen name, pinned peer identity,
  verification state, routing tag, and one Olm session.
- **Vault:** CE encrypted records and the authenticated in-memory DEK lease.
- **Secure mode:** IME state in which all normal host-output paths are gated and
  keys target the private composer.
- **Pending send:** exact encrypted wire bytes stored with advanced ratchet state
  before host insertion.
- **Pending display:** DEK-encrypted plaintext stored with advanced receive state
  only long enough to recover/show the no-history viewer.
- **Presentation:** a receiver-independent textual rendering of the same
  canonical ciphertext parts: compact `CB1`, Russian words, or English words.
  `CBW1` is recognizable deterministic camouflage, not additional encryption.
- **Verified:** local user confirmation that the Safety Number/emoji code matched
  on both physically present devices. It is not server attestation.
- **Key changed:** a peer identity differs from the pinned contact; messaging is
  blocked pending explicit re-pairing.

## Decision Sources

- `UPSTREAM.md` pins the HeliBoard origin and build baseline.
- `docs/adr/0001-crypto-library.md` records the vodozemac choice, API surface,
  audit evidence, feature flags, and alternatives.
- `docs/adr/0002-word-transport.md` records the word-presentation goals, format,
  compatibility, limitations, and dictionary provenance.
- `ARCHITECTURE.md` defines module boundaries, direct boot, IME isolation,
  storage, and crash recovery.
- `CRYPTO_PROTOCOL.md` is the normative byte/state protocol.
- `THREAT_MODEL.md` defines assets, adversaries, covered threats, and limits.
- `SECURITY_CHECKLIST.md` tracks requirements as pending until evidenced.
- `TEST_PLAN.md` maps unit, property, instrumentation, device, and release tests.
- `docs/ENVIRONMENT.md` records workstation/toolchain facts and blockers.

## Completion Standard

"Complete" means both source and evidence exist: release code has no TODO/mock
path in a required flow; all phase tests are green; real two-device pairing and
send/decrypt have passed; a signed non-debuggable APK is in `dist/`; its
certificate and SHA-256 are recorded; and independent manifest tools confirm
the absence of `android.permission.INTERNET` and every other forbidden
permission. A document, screenshot, unit test, or debug APK alone is not a
release.

The final user-facing report must state:

> Сборка реализует проверенные криптографические примитивы и прошла
> автоматические тесты, но весь продукт не следует считать независимо
> аудированным до проверки внешним специалистом по прикладной криптографии и
> Android security.
