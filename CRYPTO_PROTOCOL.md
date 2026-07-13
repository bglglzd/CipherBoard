# CipherBoard Cryptographic Protocol v1

Status: normative pre-release specification. Wire version 1 is identified by
`CB1:`. Any incompatible change to the encodings, transcript, identity binding,
or Olm configuration requires a new wire prefix/version and migration ADR.

This document specifies composition around library primitives; it does not
specify a new cipher, signature, hash, KDF, AEAD, or Double Ratchet.

## 1. Cryptographic Dependencies

CipherBoard pins `matrix-org/vodozemac` crate `0.10.0` (tag `0.10.0`, commit
`bb39ec65357989f975e0d47f9fb35e0656180151`, crates.io checksum
`b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b`).
Only one-to-one Olm is used. Megolm is not used.

Every CipherBoard session uses `SessionConfig::version_2()` with the pinned
`experimental-session-config` feature. V2 uses the full Olm MAC; V1's truncated
MAC is rejected. Default `libolm-compat`, `low-level-api`,
`insecure-pk-encryption`, `js`, and production `cfg(fuzzing)` are forbidden.

V2 remains explicitly experimental in vodozemac 0.10.0. The published 2022
Least Authority audit reviewed older commits, did not audit Android/JNI or the
Olm design itself, and did not cover this complete application or V2 as shipped
here. Version 0.10.0 is newer than the audited commits. The known advisories
fixed before 0.10.0 do not make this integration independently audited. Release
claims and the Security UI MUST state this limitation. See
`docs/adr/0001-crypto-library.md` for evidence and alternatives.

Other primitives are invoked through maintained library/platform APIs:

- SHA-256 for public transcript, fingerprint, routing, and assembly digests;
- Ed25519 signatures through the vodozemac account API;
- OS randomness through vodozemac/getrandom and Android Keystore providers;
- AES-256-GCM through Android Keystore/JCA for DEK wrapping and encrypted local
  records; and
- strict Base64url and canonical CBOR through pinned libraries.

CipherBoard does not implement these primitives.

## 2. Byte and Encoding Conventions

- All integers are unsigned. `u16`, `u32`, and `u64` concatenated into a hash
  input are big-endian.
- `H(x)` means SHA-256 over the exact byte string `x`.
- `len32(x)` is the four-byte big-endian length followed by `x`.
- Domain strings below are exact ASCII bytes including the final `0x00`.
- Random IDs are generated uniformly by the OS CSPRNG and are never derived
  from names, device identifiers, or clocks.
- Public Curve25519 and Ed25519 keys are their decoded 32-byte values, not
  human Base64 text.
- An Olm transport payload in CBOR is the bounded ASCII byte sequence returned
  by `OlmMessage::to_parts()`. The receiver validates it and passes the same
  bytes to `OlmMessage::from_parts()` with the specified numeric type.
- User text is converted once to strict UTF-8 and is not normalized, trimmed,
  case-folded, line-ending-converted, or otherwise rewritten. After decrypt,
  the body bytes MUST match the original UTF-8 bytes exactly.

### 2.1 Canonical CBOR profile

All protocol maps use unsigned integer keys and RFC 8949 deterministic
encoding: definite lengths, shortest integer/length representation, and map
keys in numeric encoded order. Floats, tags, indefinite items, duplicate keys,
and invalid UTF-8 text items are rejected. Protocol values use byte strings
rather than CBOR text unless stated otherwise.

The parser is iterative/bounded to depth 4, at most 32 map entries, at most 64
array entries, and the byte limits below. It rejects a value if re-encoding the
full parsed structure, including retained unknown extension values, does not
reproduce its canonical bytes. Keys `0..31` are core: an unknown core key is
rejected. Keys `32..255` are optional extensions and may be skipped semantically
only when absent from the message's `critical_extensions` array; their raw
bounded values are retained for canonical validation. Extension values remain
subject to all size/depth limits. Keys above 255 are rejected in v1.

## 3. Identities and Fingerprints

A fresh install/data reset creates one vodozemac `Account`. It provides a
Curve25519 identity key for Olm and an Ed25519 key for signing pairing data.
The locally chosen owner name is stored only in the vault and is not part of
identity, fingerprint, pairing, routing, or messages.

The public identity fingerprint digest is:

```text
F = H("CipherBoard identity fingerprint v1\0" || curve25519 || ed25519)
```

Human export is `CBFP1:` plus lowercase RFC 4648 Base32 of `F` without padding;
the UI groups characters for readability but parsing removes only ASCII spaces
and hyphens. A fingerprint is public comparison material, not a secret and not
a remote pairing mechanism.

Clearing application data creates unrelated identity keys. A peer MUST treat a
different identity as `KEY_CHANGED`, block the old contact session, and require
a new physical pairing. There is no automatic key replacement.

## 4. Capability Flags

Capability fields are `u64`. Bits `0..31` announce present features. Bits
`32..63` mark the corresponding low bit as required. For `flags`:

```text
present  = flags & 0xffff_ffff
required = flags >> 32
```

The receiver rejects if `required` contains an unknown bit or if
`required & present != required`.

| Low bit | Name | Meaning |
| --- | --- | --- |
| 0 | `FRAGMENT_V1` | CB1 fragmentation/reassembly |
| 1 | `SMS_COMPACT_V1` | sender selected the 152-character part profile |
| 2 | `UTF8_EXACT_V1` | body is exact, unnormalized UTF-8 |
| 3 | `OLM_V2_FULL_MAC` | vodozemac `SessionConfig::version_2()` |

Pairing and messages MUST set bits 0, 2, and 3 as present and required. SMS
parts additionally set bit 1 as present; it is not cryptographically required.
No negotiation may clear required `OLM_V2_FULL_MAC`.

## 5. Offline QR Pairing

QR data uses byte mode and ASCII-safe prefixes `CBO1:` (offer) and `CBR1:`
(response), followed by unpadded Base64url of canonical CBOR. A decoded QR is
limited to 16,384 bytes and its CBOR to the limits in section 2.1. QR parsing is
entirely local.

Offers have a configured lifetime of ten minutes and MUST NOT exceed 600
seconds (`expires_at - created_at`). Offline clock changes can affect expiry;
the persistent single-use ledger is therefore authoritative even if the clock
moves backwards.

### 5.1 Offer

Device A generates a fresh Olm one-time key, `pairing_id` (16 random bytes), and
`offer_nonce` (32 random bytes). The unsigned offer is the canonical CBOR map:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `protocol_version` | uint, exactly `1` |
| 1 | `qr_type` | uint, exactly `1` (offer) |
| 2 | `pairing_id` | bstr, 16 bytes |
| 3 | `created_at` | u64 Unix seconds |
| 4 | `expires_at` | u64, greater than created, delta <= 600 |
| 5 | `offer_nonce` | bstr, 32 bytes |
| 6 | `a_curve25519` | bstr, 32 bytes |
| 7 | `a_ed25519` | bstr, 32 bytes |
| 8 | `one_time_key_id` | bstr, 1..64 printable ASCII bytes |
| 9 | `one_time_curve25519` | bstr, 32 bytes |
| 10 | `capability_flags` | u64, section 4 |
| 11 | `critical_extensions` | array<uint>, canonical ascending, unique |

The signature input is:

```text
"CipherBoard pairing offer signature v1\0" || canonical(unsigned_offer)
```

Device A signs it with its vodozemac Ed25519 identity key. The final offer is
the same map plus key `12`, `signature` (64-byte bstr). The signature binds the
Curve25519 identity and one-time key to the displayed Ed25519 identity. Local
names and device metadata are absent.

Device A stores the exact final offer, its one-time key/account revision, expiry,
and `OFFER_CREATED` state encrypted in the vault before displaying the QR.
Cancellation/expiry deletes the pending state and the key is never reused for
another offer.

### 5.2 Import and pairing confirmation

Device B rejects an expired, non-canonical, incorrectly signed, unsupported, or
previously imported `pairing_id`. Under a vault transaction it records the
import, creates a V2 outbound session for A's Curve25519 identity and one-time
key, and encrypts exactly one Olm **pre-key** message whose plaintext is this
canonical CBOR map:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `inner_version` | uint, `1` |
| 1 | `inner_type` | uint, `0` (pairing confirmation) |
| 2 | `pairing_id` | bstr16 |
| 3 | `offer_digest` | bstr32; `H(canonical(final_offer))` |
| 4 | `response_nonce` | bstr32 generated by B |
| 5 | `a_curve25519` | bstr32 |
| 6 | `a_ed25519` | bstr32 |
| 7 | `b_curve25519` | bstr32 |
| 8 | `b_ed25519` | bstr32 |
| 9 | `negotiated_capabilities` | u64, no downgrade |
| 10 | `critical_extensions` | array<uint> |

The advanced outbound session and exact pre-key ciphertext are committed before
B displays a response. Recovery reuses that exact response and never creates a
second session from the same imported offer.

### 5.3 Response and transcript

The response core is a canonical map with keys `0..12`:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `protocol_version` | uint, `1` |
| 1 | `qr_type` | uint, `2` (response) |
| 2 | `pairing_id` | bstr16, equals offer |
| 3 | `offer_digest` | bstr32 |
| 4 | `created_at` | u64 Unix seconds, not after expiry |
| 5 | `expires_at` | u64, exactly the offer value |
| 6 | `response_nonce` | bstr32 |
| 7 | `b_curve25519` | bstr32 |
| 8 | `b_ed25519` | bstr32 |
| 9 | `negotiated_capabilities` | u64 |
| 10 | `olm_message_type` | uint, exactly `0` (pre-key) |
| 11 | `olm_payload` | bstr, 1..8192 ASCII bytes |
| 12 | `critical_extensions` | array<uint> |

Let `O` be the exact canonical final offer (including A's signature), and `R`
the exact canonical response core. The transcript hash is:

```text
T = H("CipherBoard pairing transcript v1\0" || len32(O) || O || len32(R) || R)
```

The final response adds key `13`, `transcript_hash` (bstr32 equal to `T`). B
then signs:

```text
"CipherBoard pairing response signature v1\0" ||
canonical(response_with_transcript_without_signature)
```

The final response adds key `14`, B's 64-byte Ed25519 `signature`.

Device A verifies offer ownership/state/expiry, both digests, B's signature,
capabilities, and transcript before calling
`Account::create_inbound_session(SessionConfig::version_2(), ...)`. Successful
inbound creation must decrypt the pre-key confirmation and every inner field
must match the response and original offer. In one transaction A stores the
advanced account (consumed one-time key), new session, peer identity, transcript,
routing tag, and consumed offer state. Any mismatch changes no state.

B stores the same transcript with its already advanced outbound session. Both
contacts remain `UNVERIFIED` until their respective user explicitly confirms a
physical comparison. Because v1 has no third acknowledgement QR, one device
cannot cryptographically know that the other user pressed Confirm; verification
status is deliberately local.

### 5.4 Routing tag and comparison values

The stable per-session routing tag exposed in every transport envelope is:

```text
routing_tag = first_16_bytes(
  H("CipherBoard routing tag v1\0" || T)
)
```

The numeric Safety Number is derived independently:

```text
D = H("CipherBoard numeric safety number v1\0" || T)
N = OS2IP(D) mod 10^60
```

Display `N` as exactly 60 zero-padded decimal digits in 12 groups of five. All
groups must be compared; truncation is UI-only and MUST NOT be offered as a
successful verification path.

The supplemental emoji code uses:

```text
E = H("CipherBoard emoji safety code v1\0" || T)
```

Take the high nibble then low nibble of each of the first four bytes of `E`,
yielding eight indices. Map each nibble using this exact version-1 table:

| Hex | Unicode sequence | Hex | Unicode sequence |
| --- | --- | --- | --- |
| 0 | U+2B50 | 8 | U+1F4A1 |
| 1 | U+1F511 | 9 | U+1F512 |
| 2 | U+1F514 | A | U+1F3B5 |
| 3 | U+1F4D8 | B | U+2615 |
| 4 | U+1F388 | C | U+1F332 |
| 5 | U+23F0 | D | U+1F527 |
| 6 | U+2693 | E | U+2602 U+FE0F |
| 7 | U+2708 U+FE0F | F | U+1F34E |

The numeric Safety Number is the primary comparison; emoji is a shorter
cross-check. The UI shows identity fingerprints separately.

## 6. Authenticated Inner Message

Before Olm encryption, every user message is the following canonical CBOR map:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `inner_version` | uint, exactly `1` |
| 1 | `inner_type` | uint, exactly `1` (user text) |
| 2 | `message_id` | bstr16 random |
| 3 | `routing_tag` | bstr16 |
| 4 | `sender_ed25519` | bstr32, pinned identity |
| 5 | `recipient_ed25519` | bstr32, pinned identity |
| 6 | `sender_sequence` | u64, starts at 1 and increments transactionally |
| 7 | `body_utf8` | bstr, 0..262,144 bytes, strict UTF-8 |
| 8 | `content_flags` | u64, zero in v1 |
| 9 | `critical_extensions` | array<uint> |

The outer message ID and routing tag must equal the authenticated inner values.
Sender and recipient keys bind the message to the verified pairing rather than
only to a database row. Sequence allows a receiver to label a valid delayed or
out-of-order message; it is not a trusted clock and does not make the external
transport ordered. Empty and all valid Unicode messages are allowed.

Olm's MAC authenticates the inner bytes and session. Sender authentication to a
human depends on the signed pairing transcript and explicit Safety Number
verification. Before that comparison the session is encrypted but remains
vulnerable to a pairing man-in-the-middle.

## 7. `CB1` Transport Envelope

One transport part is exactly:

```text
CB1:<unpadded-base64url(canonical-cbor-envelope)>
```

The Base64 alphabet is `A-Z a-z 0-9 - _`; padding, non-alphabet characters,
and whitespace inside a token are rejected. A selection may contain multiple
tokens separated by ASCII space, tab, CR, or LF. The collector ignores other
non-token text only when the user explicitly chooses scan-selection mode; the
strict process-text path rejects trailing or leading non-whitespace text.

The envelope map is:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `protocol_version` | uint, exactly `1` |
| 1 | `message_type` | uint, exactly `1` (Olm user message) |
| 2 | `routing_tag` | bstr16 |
| 3 | `message_id` | bstr16 |
| 4 | `olm_message_type` | uint: `0` pre-key or `1` normal |
| 5 | `part_number` | uint, 1-based |
| 6 | `part_count` | uint, 1..128; number >= part number |
| 7 | `capability_flags` | u64, section 4 |
| 8 | `olm_payload_part` | bstr, may be empty only for a one-part empty library payload (normally impossible) |
| 9 | `olm_payload_digest` | bstr32, SHA-256 of complete Olm ASCII payload |
| 10 | `critical_extensions` | array<uint> |

All parts of one message MUST have identical fields 0..4, 6..7, and 9. Part
numbers are unique and complete. Concatenating field 8 in ascending part order
must hash to field 9 before Olm parsing. The unkeyed digest is only an early
assembly/corruption check; authenticity comes from Olm and the inner bindings.

Unknown protocol version, message/Olm type, required capability, critical
extension, non-canonical CBOR, duplicate field/part, inconsistent message ID or
metadata, absent part, digest mismatch, invalid Base64, or bytes after the CBOR
root are fatal and never mutate ratchet state.

### 7.1 Limits and fragmentation profiles

| Limit | Value |
| --- | --- |
| Plaintext UTF-8 body | 262,144 bytes |
| Complete Olm ASCII payload | 524,288 bytes |
| Parts per message | 128 |
| Decoded CBOR per Universal part | 16,384 bytes |
| One encoded Universal token | 24,000 ASCII characters |
| One SMS compact token | 152 ASCII characters |
| Aggregate selected input | 3,145,728 bytes |
| Incomplete assemblies | 16 globally, 4 per routing tag |
| Incomplete assembly lifetime | 24 hours elapsed time while app data persists |

Universal mode uses the largest field-8 slice that keeps decoded CBOR at or
below 16,384 bytes and the encoded token at or below 24,000 characters. SMS
compact mode searches downward for the largest slice whose complete `CB1`
token is at most 152 ASCII characters and sets capability bit 1. The fragmenter
first computes the resulting part count and refuses the operation if it exceeds
128. It never silently switches profiles.

The UI estimates GSM-7 concatenated SMS count (160 septets for one segment,
153 per concatenated segment) but labels it an estimate because transport apps
may add separators or transcode. SMS parts are individually self-describing,
need no spaces, and may arrive in any order. CipherBoard does not decrypt until
all parts are present. Universal parts may be joined with newline for one
`commitText` call. Plaintext is not compressed.

## 8. Replay, Ordering, and Ratchet State

`message_id` uniqueness is checked at send creation and recorded at receive in
the same transaction as the advanced session. The replay ledger is bounded by
a documented retention policy but MUST retain at least 4,096 received IDs per
contact; eviction never restores an Olm message key. A duplicate is rejected
either by the ledger or by vodozemac's missing-message-key result.

The receiver keeps a high sender sequence and a bounded seen window. A lower
previously unseen sequence that Olm can decrypt is accepted and marked
out-of-order; an already seen sequence is replay. Gaps are reported without
claiming that the missing transport message was maliciously delayed. Arbitrary
delay and global ordering cannot be prevented in a serverless text transport.

CipherBoard does not raise vodozemac's high-level limits: five stored receiving
chains, up to 40 skipped message keys per chain, and maximum forward gap 2000.
Thus out-of-order support is bounded, not unlimited. Used message keys are not
retained for history. Send and receive for one session are serialized and every
mutation uses a monotonic persisted revision.

The crash-consistent state transitions in `ARCHITECTURE.md` are part of the
protocol implementation requirement: state plus pending ciphertext on send,
and state plus replay plus encrypted pending display on receive, commit before
publication. Retrying a pending send reuses exactly the same `CB1` bytes.

## 9. Reset, Re-pair, and Failure Rules

- Authentication/MAC, format, identity, routing, transcript, replay, part, or
  UTF-8 failure changes no session/account state.
- Unknown stored schema or vodozemac pickle version fails closed as `SESSION_ERROR`;
  it is never deserialized optimistically.
- Manual session reset destroys the local session and sets `PAIRING_REQUIRED`.
  It does not create a replacement session from old QR data.
- Re-pairing uses new pairing IDs/nonces/one-time keys and a new transcript.
  Old routing tags and sessions are not accepted by the replacement contact.
- Contact deletion removes encrypted local records and keys/references on a
  best-effort Android basis. Previously exported ciphertext remains in external
  applications but is not made decryptable by preserving message keys.
- Keystore invalidation makes the vault unrecoverable. After explicit user
  acknowledgement the only supported recovery is destructive identity reset
  and physical re-pairing.

## 10. Required Protocol Evidence

Before `CB1` is declared stable, release artifacts MUST include golden vectors
for identity fingerprints, offer/response signatures, transcript hash, routing
tag, numeric/emoji comparisons, inner CBOR, one/multipart envelopes, Base64url,
and Unicode byte equality. Independent Alice/Bob states must exercise first
pre-key creation, bidirectional traffic, 1000 messages, gaps, reordering,
mutation, replay, concurrent calls, transaction crash points, deletion, and
re-pairing. Property and fuzz tests must prove that arbitrary parser input
cannot panic or allocate beyond limits.

Passing those tests is not equivalent to an independent cryptographic or
Android security audit.
