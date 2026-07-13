# Security Policy

CipherBoard handles keyboard input, identity keys, and Double Ratchet state.
Please report security issues privately and avoid creating a public record that
could expose users before a fix is available.

Reports are accepted in English or Russian.

## Supported Versions

CipherBoard is pre-1.0. Security fixes target the current development branch and
the latest published release, if one exists. Older builds, source snapshots,
debug APKs, and third-party repackaged APKs do not receive guaranteed backports.

| Version | Security support |
| --- | --- |
| Current development branch | Best-effort fixes |
| Latest repository release | Best-effort fixes |
| Older or third-party builds | Not supported |

This policy is not a claim that any version is independently audited or suitable
for high-risk deployment.

## Reporting a Vulnerability

Prefer GitHub private vulnerability reporting:

1. Open this repository's **Security** tab.
2. Open **Advisories**.
3. Choose **Report a vulnerability** and create a private draft advisory.

If the repository does not expose private vulnerability reporting, do not put
technical details, proof of concept, or affected user data in a public issue.
Open a minimal issue asking the maintainers to establish a private channel, or
use another private contact method published by the repository owner.

Do not send security material to the upstream HeliBoard project unless the issue
is independently reproducible in unmodified HeliBoard and contains no
CipherBoard user data.

## What to Include

A useful report contains:

- the affected CipherBoard version, source commit, and APK SHA-256;
- device model, Android or GrapheneOS build, and relevant Vault security level;
- a concise description of the affected trust boundary and potential impact;
- deterministic reproduction steps using synthetic identities and messages;
- whether the issue requires an unlocked device, malicious host app,
  Accessibility service, root, physical access, or a modified APK;
- the earliest known affected version and any proposed mitigation; and
- sanitized test code or a minimal proof of concept when necessary.

Never include real plaintext, complete production ciphertext, contact names,
full identity fingerprints, Safety Numbers, pairing QR payloads, private keys,
account/session pickles, Vault databases, signing keys, passwords, or unrelated
device identifiers. Generate disposable test identities and messages instead.

## In Scope

Examples include:

- plaintext reaching a host editor, clipboard, saved state, logs, backup,
  notification, accessibility dump, screenshot, recents preview, or persistent
  file;
- ratchet rollback, message-key reuse, replay acceptance, skipped-key abuse, or
  non-atomic pending operations;
- identity substitution, pairing replay, transcript mismatch, Safety Number
  inconsistency, or silent key-change acceptance;
- signature, AEAD, canonical-envelope, parser-bound, or JNI memory-safety flaws;
- Keystore policy bypass, software-key fallback, unauthenticated Vault access,
  secret backup/restore, or cross-record substitution;
- an unexpected network path, forbidden permission, telemetry SDK, exported
  component, intent validation flaw, or plaintext data exfiltration; and
- a vulnerable dependency that is reachable in the packaged runtime.

## Known Model Limitations

The following are important limitations but are not automatically new
vulnerabilities:

- a fully compromised unlocked device, root/kernel exploit, or maliciously
  modified CipherBoard APK;
- a malicious Accessibility service, camera pointed at the screen, shoulder
  surfing, physical coercion, and transport metadata analysis;
- inability to guarantee immediate JVM/Android UI memory erasure;
- the non-absolute nature of `FLAG_SECURE`;
- loss of convenient re-decryption when plaintext history and message keys are
  deliberately not retained; and
- absence of an independent product audit.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and
[`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for the authoritative boundary and
current evidence. A demonstrated bypass of an intended control remains in scope
even when it involves one of these areas.

## Handling and Disclosure

Maintainers will validate reports as capacity permits, coordinate fixes in a
private advisory when possible, and credit reporters who request attribution.
There is no guaranteed response-time SLA or bug bounty.

Please allow time for a patch, regression tests, signed release, and user
upgrade guidance before public disclosure. If a report is not applicable,
already known, or outside the documented model, maintainers should explain the
reason without disclosing sensitive reporter data.

## Release Verification

A source fix is not complete until the exact release artifact passes the
repository's manifest, permission, ABI, signing, dependency, and checksum gates.
Users should independently verify both the APK SHA-256 and the signing
certificate fingerprint. See [`RELEASE.md`](RELEASE.md).
