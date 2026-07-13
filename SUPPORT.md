# CipherBoard Support

CipherBoard is a pre-1.0 open-source project maintained on a best-effort basis.
It does not provide emergency response, guaranteed availability, account
recovery, remote key recovery, or professional security assurance.

Questions and reports are welcome in English or Russian.

## Where to Ask

- **Reproducible application bug:** use the repository bug-report template.
- **Feature proposal:** use the feature-request template and describe the
  offline, privacy, security, and usability impact.
- **Build or contribution question:** open a focused discussion if the
  repository enables GitHub Discussions; otherwise use an issue without secret
  data.
- **Documentation problem:** open an issue and identify the file and section.
- **Security vulnerability:** do not open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- **Problem in unmodified HeliBoard:** report it here first unless you have
  confirmed it against official HeliBoard. Maintainers can then identify whether
  an upstream report is appropriate.

Search existing open and closed issues before filing a new one. Keep one topic
per issue.

## Safe Diagnostic Information

Include only what is necessary:

- exact CipherBoard version and source commit, if self-built;
- APK source and SHA-256, without attaching a private APK;
- device model and Android/GrapheneOS version;
- whether Sandboxed Google Play is absent or present;
- displayed Keystore security level (`StrongBox` or `TEE`), without device
  attestation identifiers;
- keyboard language/layout, host-app category, and field type;
- steps using synthetic contacts and messages; and
- sanitized error codes and test results.

Do not post real message text, complete ciphertext, contact names, full
fingerprints, Safety Numbers, QR payloads, Vault files, private keys, session
state, signing material, screenshots containing private conversations, or
logcat output that has not been reviewed and redacted. CipherBoard intentionally
avoids logging message content, but other applications and the operating system
may not.

## Common Checks

Before reporting an installation or runtime problem:

1. Verify the APK SHA-256 and signing certificate fingerprint.
2. Confirm that CipherBoard is enabled under Android's on-screen keyboard
   settings.
3. Confirm that the device has a strong PIN or password and credential-encrypted
   storage is unlocked.
4. Grant Camera only while testing QR scanning. Contacts, SMS, storage, and
   Network access are not required.
5. Pair in person, scan both QR codes, and compare the entire Safety Number.
6. Reproduce with a disposable contact and synthetic text.
7. For build failures, compare the installed JDK, SDK, Build Tools, NDK, Rust,
   and Cargo versions with [`BUILD.md`](BUILD.md).

Deleting application data or reinstalling CipherBoard creates a new identity.
Existing contacts must pair again; old sessions cannot be recovered from a
server or cloud backup.

## High-Risk Use

The project has not received an independent complete security audit. Before
high-risk use, independently review the exact source and signed APK, test the
intended workflow on physical GrapheneOS devices, validate StrongBox/TEE and
screen-protection behavior, disable GrapheneOS Network permission as defense in
depth, and establish a safe fallback communication plan.

Read [`THREAT_MODEL.md`](THREAT_MODEL.md) and
[`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) before relying on CipherBoard's
security properties.
