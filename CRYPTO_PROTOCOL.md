# CipherBoard Protocol: Implemented Snapshot

**Snapshot date:** 2026-07-14

**Wire version:** provisional `1`

**Release status:** not stable and not approved for production interoperability

This document describes the bytes currently produced and accepted by
`crypto-core/native`. It is deliberately descriptive, not an assertion that
the protocol satisfies every CipherBoard v1 requirement. Open gaps are listed
in section 11. A future incompatible correction must change the wire prefix or
protocol version; it must not silently reinterpret already emitted version-1
bytes.

The implementation sources of truth are `account.rs`, `pairing.rs`,
`session.rs`, `envelope.rs`, and `presentation.rs`. Android storage and
publication ordering are described in `ARCHITECTURE.md`. The word-presentation
decision and its non-security goals are recorded in
`docs/adr/0002-word-transport.md`.

## 1. Cryptographic Dependency

CipherBoard pins `matrix-org/vodozemac` crate `0.10.0` (tag `0.10.0`, commit
`bb39ec65357989f975e0d47f9fb35e0656180151`, crates.io checksum
`b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b`).
Only one-to-one Olm is used. Every session is created with
`SessionConfig::version_2()`; Megolm is not used.

Vodozemac 0.10.0 labels the v2 session configuration experimental. The
published Least Authority review covered older vodozemac commits and did not
audit this Android/JNI/storage/UI integration or this complete wire protocol.
Use of the library is not an independent audit of CipherBoard. See
`docs/adr/0001-crypto-library.md`.

CipherBoard uses vodozemac for Curve25519, Ed25519, Olm/Double Ratchet and its
randomness. SHA-256 is provided by the Rust `sha2` crate. Android storage uses
JCA/Keystore AES-256-GCM. The project does not implement these primitives.

## 2. Common Encoding Rules

- `H(x)` is SHA-256 over the exact bytes `x`.
- All domain labels below are ASCII and include the final NUL byte shown as
  `\0`.
- QR and message tokens use RFC 4648 Base64url without padding.
- Protocol integers are unsigned and use the shortest CBOR representation.
- User message bodies are byte arrays. The Rust core does not normalize them.
  The Android composer performs strict UTF-8 encoding and the viewer performs
  strict UTF-8 decoding.
- Random pairing IDs and message IDs are 16 bytes. Pairing nonces are 32 bytes.
- Capability values are currently opaque `u32` values. There is no implemented
  required-bit registry or critical-extension negotiation.

Pairing objects are fixed-length CBOR arrays. Transport envelopes are canonical
CBOR maps. These are intentionally distinguished below.

## 3. Identity and Routing

A vodozemac account supplies a 32-byte Curve25519 identity key and a 32-byte
Ed25519 identity key. Local owner and contact names are storage/UI metadata and
do not enter crypto-core protocol objects.

The implemented 32-byte identity fingerprint is:

```text
H("CipherBoard Identity v1\0" || curve25519 || ed25519)
```

No stable `CBFP1` public export encoder is implemented in the current runtime.

The implemented routing tag is derived from the two public identities, not the
pairing transcript. Let each identity be `curve25519 || ed25519`, sort the two
64-byte values lexicographically as `first, second`, then compute:

```text
first_16_bytes(H("CipherBoard Routing v1\0" || first || second))
```

Consequently, re-pairing the same two identities currently reuses a routing
tag. Transcript-specific routing remains a protocol-hardening blocker.

Serialized account and session snapshots are internal state, not transport
formats. They are prefixed `CBA1` and `CBS1` respectively and contain bounded
vodozemac pickles. Session snapshots also contain the pinned local/remote
identities, routing tag, and up to 4096 seen message IDs. Android must wrap
these snapshots in authenticated encrypted vault records before persistence.

## 4. Pairing Offer (`CBO1`)

Text form is:

```text
CBO1:<unpadded-base64url(fixed-cbor-array)>
```

The final offer is a definite CBOR array of 10 elements, in order:

| Index | Value |
| --- | --- |
| 0 | protocol version `1` |
| 1 | object type `1` (offer) |
| 2 | random pairing ID, bstr16 |
| 3 | A Curve25519 identity, bstr32 |
| 4 | A Ed25519 identity, bstr32 |
| 5 | A generated Olm one-time Curve25519 key, bstr32 |
| 6 | offered capabilities, `u32` |
| 7 | expiration as Unix epoch seconds, `u64` |
| 8 | random offer nonce, bstr32 |
| 9 | Ed25519 signature, bstr64 |

Elements 0 through 8 form the unsigned offer array. The signature input is:

```text
"CipherBoard Pairing Offer v1\0" || canonical(unsigned_offer_array)
```

Offer creation accepts a TTL from 1 through 900 seconds and stores only the
resulting expiration. The wire object has no creation time or one-time-key ID.
The decoder verifies exact array length, field sizes, signature, trailing-byte
absence, and byte-for-byte canonical re-encoding. `now > expires_at` is expired;
equality is still accepted. Because creation time is absent, a decoder cannot
independently prove that an offer produced by another implementation had a
maximum 900-second lifetime.

The offer hash used by the response is:

```text
offer_hash = H(canonical(final_offer_array))
```

## 5. Pairing Response (`CBR1`)

Device B verifies the offer and expiration, creates an Olm v2 outbound session,
and encrypts this fixed CBOR array as its first Olm pre-key plaintext:

| Index | Value |
| --- | --- |
| 0 | protocol version `1` |
| 1 | pairing ID, bstr16 |
| 2 | offer hash, bstr32 |
| 3 | B response nonce, bstr32 |

The final response text is `CBR1:` plus unpadded Base64url of a definite CBOR
array of 11 elements:

| Index | Value |
| --- | --- |
| 0 | protocol version `1` |
| 1 | object type `2` (response) |
| 2 | pairing ID, bstr16 |
| 3 | B Curve25519 identity, bstr32 |
| 4 | B Ed25519 identity, bstr32 |
| 5 | offer hash, bstr32 |
| 6 | random response nonce, bstr32 |
| 7 | Olm message type, currently required to become a pre-key message during completion |
| 8 | non-empty Olm ASCII payload as bstr, at most 32 KiB |
| 9 | `offer_capabilities & local_capabilities`, `u32` |
| 10 | B Ed25519 signature, bstr64 |

Elements 0 through 9 form the unsigned response. The signature input is:

```text
"CipherBoard Pairing Response v1\0" || canonical(unsigned_response_array)
```

Device A additionally checks matching pairing ID and offer hash, ensures the
response capability bits are a subset of the offer, requires an Olm pre-key
message, creates the inbound session on a private account copy, and checks the
encrypted four-element binder. Only then is the caller's account advanced.
Persisting that advanced account makes a second completion fail because the
one-time key has been consumed.

The Rust responder does not mutate account state and does not itself remember
imported pairing IDs. Durable duplicate-import/single-response enforcement on
device B therefore depends on the Android pending-pairing ledger. The current
Android coordinator stages the encrypted responder session and exact response
under the pairing ID, returns that same response for the same still-active
offer, and rejects consumed, expired, cancelled, or conflicting state. Contact,
initial ratchet, and pending-state consumption are committed together only
after the responder explicitly confirms the displayed comparison values. This
integration also exposes explicit unfinished-pairing deletion and performs
bounded expiry/orphan cleanup that cancels active state and tombstones staged
session material. It has JVM state-machine coverage but not process-kill or
live two-device evidence.

The QR library additionally limits decoded text to 16,384 ASCII bytes, while
crypto-core accepts pairing text up to 32 KiB. The stricter Android QR limit is
the effective camera path limit.

## 6. Safety Comparison

Both sides currently compute:

```text
S = H("CipherBoard Safety v1\0" || final_offer_array || final_response_array)
```

The numeric representation covers all 256 bits by splitting `S` into eight
big-endian `u32` values and formatting each as exactly 10 decimal digits. The
result is eight space-separated groups, 80 digits total.

The supplementary word code takes the high and low nibble of each of the first
four bytes and maps the eight nibbles to this fixed table:

```text
0 amber   1 birch   2 cloud   3 dawn
4 elm     5 frost   6 glass   7 harbor
8 iris    9 jade    A kite    B linen
C maple   D north   E opal    F pine
```

Android displays both implemented values to each role and requires explicit
local confirmation before persisting a verified contact. Both are derived from
the same transcript hash, as required; the product requirements do not mandate
a particular digit count or require emoji instead of a word code. The current
80-digit/eight-word rendering is therefore the provisional version-1 rendering,
not a mismatch. The ceremony has not yet been exercised with two physical
devices and cameras.

## 7. Authenticated Inner User Message

The current inner plaintext passed to Olm is a definite CBOR array of four
elements:

| Index | Value |
| --- | --- |
| 0 | inner version `1` |
| 1 | random message ID, bstr16 |
| 2 | capabilities, `u32` |
| 3 | user bytes, bstr, at most 192 KiB |

On receive, inner message ID and capabilities must exactly match the outer
reassembled envelope. Olm authenticates the inner bytes and ratchet session.
The current inner object does not separately repeat sender/recipient identity,
routing tag, content type, or sequence number. Those proposed bindings are not
implemented and must not be claimed.

The Rust API permits an empty byte body. The current Android composer refuses
an empty editor value, so empty-message product support is not end-to-end.

## 8. Transport Envelope (`CB1`)

One part is:

```text
CB1:<unpadded-base64url(canonical-cbor-map)>
```

The implemented map has nine mandatory unsigned integer keys:

| Key | Value |
| --- | --- |
| 0 | protocol version `1`, `u8` |
| 1 | message type `1`, `u8` |
| 2 | routing tag, bstr16 |
| 3 | message ID, bstr16 |
| 4 | Olm message type `0` or `1`, `u8` |
| 5 | this part's Olm payload bytes, bstr |
| 6 | one-based part number, `u16` |
| 7 | total parts, `u16`, 1 through 128 |
| 8 | capabilities, `u32` |

Unknown keys 9 through 127 are rejected as mandatory. Keys 128 and above are
accepted only for a bounded scalar (`bool`, `null`, signed/unsigned integer) or
a byte/text string of at most 1024 bytes. Arrays, maps, tags, floats and
indefinite values are rejected. There is no implemented `critical_extensions`
array.

The parser enforces a definite map of at most 32 fields, strictly increasing
canonical integer keys, no duplicates, shortest integer/map/string encodings,
exact fixed-size fields, no trailing bytes, Base64url alphabet without padding,
and a maximum encoded token length of 32 KiB. Regression tests reject
non-shortest map lengths, keys and optional scalar values.

Every part must agree on routing tag, message ID, Olm type, total count and
capabilities. Part numbers must be unique and complete; input order is
irrelevant. Reassembled Olm bytes are limited to 256 KiB. There is no outer
whole-payload digest field. Corruption is ultimately rejected by Olm
authentication and the authenticated inner message bindings, but the omitted
early assembly digest remains a design difference from the requested format.

## 9. Presentation and Fragmentation Limits

| Property | Implemented value |
| --- | --- |
| Android composer plaintext, Compact | non-empty, at most 192 KiB after UTF-8 encoding |
| Android composer plaintext, Russian/English words | non-empty, at most 32 KiB after UTF-8 encoding |
| Rust plaintext body | 192 KiB |
| Reassembled Olm payload | 256 KiB |
| Parts | 128 |
| Encoded token | 32 KiB |
| Universal chunk | 16 KiB of Olm payload |
| Word wrapper after Base4096 decode | 48 KiB |
| Word tokens | 32,768 |
| Android presentation input | 384 Ki UTF-16 code units |

New sends always use the universal 16-KiB fragmentation profile. The former
Android **SMS compact** selector is removed. The parser still accepts canonical
legacy `CB1` part sets created with the old 48-byte profile because chunk size
is not a protocol field and the normal consistency and size limits still apply.

After the ordered canonical `CB1` parts are built, the sender selects one of
three presentation layers:

| Presentation | External text | Compatibility |
| --- | --- | --- |
| Compact | canonical `CB1:` tokens separated by newline | current and older CipherBoard versions |
| Russian words | `CBW1` Base4096 using the pinned Russian 4096-word list | CipherBoard 0.4+ |
| English words | `CBW1` Base4096 using the pinned English 4096-word list | CipherBoard 0.4+ |

The two word formats wrap the complete ordered canonical parts; they do not
replace the canonical envelope or modify the Olm ciphertext. Their decoded
binary wrapper is:

```text
tag[8] || "CBW" || version[1] || alphabet[1] || flags[1] ||
part_count_be[2] || body_length_be[4] ||
repeat(part_length_be[4] || canonical_CB1_cbor_bytes)
```

`version` is `1`, so this presentation family is called `CBW1`. `alphabet` is
`1` for Russian and `2` for English; flags are currently zero. The 8-byte tag
comes first and is the first 8 bytes of
`SHA-256("CipherBoard Word Transport v1\0" || wrapper_without_tag)`. It is a
checksum for early corruption rejection, not authentication and not a MAC.
Message authenticity and integrity continue to come only from the unchanged
Olm/AEAD payload and its inner/outer bindings.

`CBW1` is the internal magic/version name, not a literal visible prefix. Because
the tag is the first binary field and the whole wrapper is Base4096-encoded, the
external text begins with dictionary words derived from the tag.

The complete wrapper is encoded most-significant-bit first in 12-bit values;
each value indexes one token in the selected, version-pinned 4096-word
dictionary. Tokens are separated with bounded ASCII transport whitespace.
Decode determines
the alphabet from the first token, enforces zero padding and exact declared
length/count, reconstructs the exact `CB1:` parts, and runs the normal canonical
part validation before decryption. It rejects mixed/unknown words, edits,
truncation, extra tokens, reordered parts, inconsistent metadata, more than
32,768 words, a decoded wrapper over 48 KiB, or Android input over 384 Ki UTF-16
code units. The lower-level JNI text boundary is also bounded; no path allocates
from an untrusted declared length without validation.

Presentation is a local sender preference and is not negotiated or stored in a
contact/session. Receivers on 0.4+ auto-detect all three forms, independent of
their own send preference. Word output is not a natural-language sentence,
steganography, or plausible deniability. It is longer and more fragile under
autocorrect, translation, token edits, and messenger transformations than
compact `CB1`, while exposing substantially the same timing, sender, recipient,
and approximate-size metadata.

The parser does not persist incomplete assemblies: selected text must contain
all parts, either directly or inside one word wrapper, in one invocation. There
is no 24-hour partial-message collector in the current application.

## 10. Replay and Atomic Android State

The serialized session holds up to 4096 seen message IDs. A duplicate is
rejected from that ledger or by vodozemac when its message key is no longer
available. Vodozemac's own skipped-message limits bound out-of-order delivery.

The Android runtime implements these publication boundaries:

- send: advanced encrypted ratchet state and exact pending ciphertext are
  committed in one SQLite transaction before the composer asks the live IME to
  call `InputConnection.commitText()` through a one-shot handoff bound to the
  originating host/editor and contact;
- receive: replay row, advanced encrypted ratchet state and an encrypted
  pending-display plaintext record are committed in one SQLite transaction
  before the viewer opens that record; the pending record is bound to the
  digest of the exact ordered ciphertext parts;
- abandoning a display lease before render retains that encrypted record for
  an exact-ciphertext retry; closing a rendered lease deletes it; and
- completing a successful host insertion deletes the contact-bound pending-
  outbound record, while a failed/mismatched handoff keeps the exact bytes for
  retry without a new ratchet step.

These source-level transactions, retry/recovery paths and JVM unit tests are
implemented. Forced process-crash instrumentation at every boundary and the
ambiguous host-accepted/status-crash case have not yet been demonstrated on
Android.

## 11. Protocol Blockers Before a Stable v1

1. Decide and version the pairing/envelope/inner schemas; the previous
   aspirational document did not match emitted bytes.
2. Validate the integrated Android pairing persistence/UI, B-side
   duplicate-import ledger, bounded orphan cleanup, expiry/cancel handling,
   explicit verification, identity-change blocking and re-pair flow with live
   two-device and process-kill tests. Add a signed creation time or otherwise
   make the maximum original TTL enforceable by the receiving device; the wire
   currently carries only the claimed expiry.
3. Define capability semantics and downgrade handling; current `u32`
   intersection has no required-feature policy.
4. Decide whether routing must be transcript-specific and whether sender,
   recipient, sequence and routing fields must be repeated inside Olm.
5. Decide whether an outer assembly digest is required and version any change.
6. Add stable golden vectors and an independent decoder/oracle for every final
   field, domain separator and limit.
7. Run sustained coverage-guided fuzzing and Android forced-crash/restart tests.

Passing current automated tests is not equivalent to independent protocol or
product security review.
