<p align="center">
  <img src="app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" width="120" height="120" alt="CipherBoard application icon">
</p>

<h1 align="center">CipherBoard</h1>

<p align="center">
  <strong>Write privately. Send anywhere.</strong><br>
  An offline encrypted Android keyboard for physically QR-paired messaging.
</p>

<p align="center">
  <a href="https://github.com/bglglzd/CipherBoard/releases/latest"><img src="https://img.shields.io/github/v/release/bglglzd/CipherBoard?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=2ea44f" alt="Latest release"></a>
  <a href="https://github.com/bglglzd/CipherBoard/releases"><img src="https://img.shields.io/github/downloads/bglglzd/CipherBoard/total?style=flat-square&amp;color=0969da" alt="Total downloads"></a>
  <img src="https://img.shields.io/badge/secure_mode-Android_11%2B-3ddc84?style=flat-square&amp;logo=android&amp;logoColor=white" alt="Android 11 or newer for secure messaging">
  <img src="https://img.shields.io/badge/network_permission-none-6f42c1?style=flat-square" alt="No network permission">
  <img src="https://img.shields.io/badge/ABI-arm64--v8a-555?style=flat-square" alt="arm64-v8a release ABI">
</p>

<p align="center">
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/ci.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/security.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/security.yml/badge.svg?branch=main" alt="Security checks status"></a>
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/codeql.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL status"></a>
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/instrumentation.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/instrumentation.yml/badge.svg?branch=main" alt="Android instrumentation status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square" alt="GPL-3.0-only license"></a>
</p>

<p align="center">
  <a href="#download"><strong>Download</strong></a> &nbsp;|&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;|&nbsp;
  <a href="#security-model">Security</a> &nbsp;|&nbsp;
  <a href="docs/GRAPHENEOS.md">GrapheneOS guide</a> &nbsp;|&nbsp;
  <a href="#documentation">Documentation</a>
</p>

CipherBoard turns the keyboard into a protected compose-and-read surface. Two
people pair in person, verify the same Safety Number, and exchange encrypted
text through any app that can carry text. There are no CipherBoard accounts,
servers, phone numbers, or network requests.

> [!WARNING]
> CipherBoard is pre-1.0 security-sensitive software. It uses reviewed
> cryptographic primitives and extensive automated checks, but the complete
> product has not received an independent applied-cryptography and Android
> security audit. Do not treat it as audited or risk-free.

## Why CipherBoard

| | |
| --- | --- |
| **Offline by design** | No Internet permission, analytics, ads, cloud backup, account system, or CipherBoard server. |
| **Physical trust setup** | Two-way QR pairing and an in-person Safety Number comparison establish each contact. |
| **Protected writing** | Private drafts stay in CipherBoard's IME panel; the host app receives only persisted ciphertext. |
| **Protected reading** | Plaintext is drawn read-only in a `FLAG_SECURE` panel without selection, clipboard export, autofill, or Accessibility text. |
| **Modern sessions** | Pinned `vodozemac` Olm sessions provide per-message keys, forward secrecy, replay handling, and out-of-order delivery support. |
| **Use any transport** | Send the resulting text through SMS, email, Telegram, Signal, or another text-capable app. CipherBoard never sends it itself. |

## Download

<p align="center">
  <a href="https://github.com/bglglzd/CipherBoard/releases/latest/download/CipherBoard-0.4.2-release.apk"><img src="https://img.shields.io/badge/Download-CipherBoard_0.4.2_APK-2ea44f?style=for-the-badge&amp;logo=android&amp;logoColor=white" alt="Download CipherBoard 0.4.2 APK"></a>
</p>

The current production build is **CipherBoard 0.4.2** for `arm64-v8a` devices.
Open the [latest release](https://github.com/bglglzd/CipherBoard/releases/latest)
for release notes and verification evidence.

| Release file | Purpose |
| --- | --- |
| `CipherBoard-0.4.2-release.apk` | **Install this file.** It is the only application package. |
| `CipherBoard-0.4.2-release.apk.sha256` | Optional checksum for verifying the APK download. |
| Other attachments | Build, source, SBOM, license, and vulnerability-scan evidence for auditors. Do not install them. |
| GitHub's `Source code` archives | Automatic source snapshots, not Android applications. |

> [!IMPORTANT]
> Update in place. Do not uninstall CipherBoard or clear its app data before an
> update: that destroys the Vault, local identity, contacts, and ratchet state.
> Stop if Android reports a signing-certificate mismatch.

Verify the APK checksum before installation:

```sh
sha256sum --check CipherBoard-0.4.2-release.apk.sha256
adb install -r CipherBoard-0.4.2-release.apk
```

On Windows PowerShell:

```powershell
(Get-FileHash .\CipherBoard-0.4.2-release.apk -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\CipherBoard-0.4.2-release.apk.sha256
adb install -r .\CipherBoard-0.4.2-release.apk
```

If Android Build Tools are installed, verify the signature and compare the
certificate SHA-256 with [`SIGNING_CERTIFICATE_SHA256`](SIGNING_CERTIFICATE_SHA256)
through a separately trusted channel:

```sh
apksigner verify --verbose --print-certs CipherBoard-0.4.2-release.apk
```

For stable update notifications without giving CipherBoard network access, add
`https://github.com/bglglzd/CipherBoard` to Obtainium, leave pre-releases
disabled, and use this release-asset filter:

```regex
^CipherBoard-[0-9]+\.[0-9]+\.[0-9]+-release\.apk$
```

Obtainium is an optional external installer and a separate networked trust
boundary. CipherBoard itself neither checks for nor installs updates. See the
complete [GrapheneOS installation and update guide](docs/GRAPHENEOS.md).

## How It Works

1. Each device creates a local cryptographic identity inside an authenticated
   Android Keystore-backed Vault.
2. The devices pair in person by scanning an offer QR and a response QR.
3. Both people compare the complete Safety Number before verifying the contact.
4. The sender opens CipherBoard, taps the shield, chooses a verified contact,
   and writes with the on-screen keys in **Encrypt** mode.
5. CipherBoard commits the advanced Olm ratchet before inserting only encrypted
   text into the host application.
6. The recipient copies the complete message, opens **Decrypt**, and taps
   **Paste and decrypt**. Compact, Russian-word, and English-word presentations
   are detected automatically.
7. Plaintext is displayed only in CipherBoard's protected read-only panel.
   **Reply securely** clears it and returns to the selected contact in Encrypt
   mode.

Compact `CB1:` is shortest and remains compatible with older CipherBoard
versions. Word presentation is optional camouflage from a casual glance, not
natural language, steganography, plausible deniability, or extra encryption.
Both peers need CipherBoard 0.4 or newer for word-form messages.

## Security Model

### Enforced controls

- No `android.permission.INTERNET`, network-state permission, Firebase, Google
  Play Services, telemetry, advertising, or crash-reporting SDK is in the
  runtime design.
- Pairing is serverless and requires a physical two-way QR exchange.
- Vault records use a random data-encryption key wrapped by a non-exportable,
  hardware-backed Android Keystore key. StrongBox is attempted first; verified
  TEE is the fallback. Software-only keys are rejected.
- Ratchet, replay, and pending-operation state is committed transactionally
  before ciphertext leaves the IME or plaintext is displayed.
- Private mode disables personalized learning, suggestions, clipboard history,
  copy/cut/paste, saved view state, and content capture. Only the on-screen
  keyboard is supported for private drafts.
- Backup and device-transfer extraction are disabled for application data.
- Transport, word-presentation, and QR parsers use strict canonical encoding,
  explicit limits, and malformed-input rejection.
- Published releases pin the signing certificate and independently verify the
  APK, native hardening, exact source, SBOM, offline vulnerability report, and
  release hashes.

### Explicit limitations

CipherBoard cannot protect an unlocked device with a compromised OS, malicious
Accessibility service, modified APK, or privileged attacker. It cannot prevent
a camera or nearby person from seeing the screen, hide transport metadata,
resist physical coercion, or guarantee complete JVM/Android memory erasure.
`FLAG_SECURE` and best-effort clearing are useful controls, not absolute
guarantees.

The normal keyboard retains HeliBoard behavior and may use learning or clipboard
features according to its settings. The stricter boundary applies to Private
mode and the protected viewer. Android can route a hardware keyboard directly
to the host app, so private drafts must use CipherBoard's on-screen keys.

Read the complete [threat model](THREAT_MODEL.md),
[protocol specification](CRYPTO_PROTOCOL.md), and
[security review](SECURITY_REVIEW.md) before evaluating CipherBoard for
sensitive use.

## Project Status

| Project fact | Current value |
| --- | --- |
| Maturity | Pre-1.0; current version `0.4.2` |
| Application ID | `org.cipherboard.securekeyboard` |
| Android baseline | `minSdk 23`, `targetSdk 36`; acceptance target is current GrapheneOS |
| Release ABI | `arm64-v8a`; debug builds also include `x86_64` for emulators |
| Runtime network | No Internet or network-state permission; no runtime network feature |
| Interface languages | English and Russian |
| Latest notes | [CipherBoard 0.4.2](docs/releases/v0.4.2.md) |

CipherBoard is an unofficial modified fork of HeliBoard. It is not an official
HeliBoard release and is not endorsed or supported by the HeliBoard project.

## Build From Source

The pinned environment and complete release procedure are documented in
[`BUILD.md`](BUILD.md) and [`RELEASE.md`](RELEASE.md). The short debug path is:

```sh
./scripts/build-debug.sh
```

```powershell
.\scripts\build-debug.ps1
```

The scripts run source-policy checks, Android lint, module unit tests, build the
APK, and verify its manifest policy. A production release additionally requires
a clean worktree, external signing material, Rust checks, Android device tests,
an offline vulnerability database, and exact artifact verification.

## Documentation

| Document | Scope |
| --- | --- |
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | Product scope and invariants |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Components and trust boundaries |
| [`CRYPTO_PROTOCOL.md`](CRYPTO_PROTOCOL.md) | Wire format and protocol state |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Threats, assumptions, and limitations |
| [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md) | Security requirement traceability |
| [`TEST_PLAN.md`](TEST_PLAN.md) | Test matrix and acceptance evidence |
| [`docs/GRAPHENEOS.md`](docs/GRAPHENEOS.md) | Installation and external updates |
| [`UPSTREAM.md`](UPSTREAM.md) | Exact HeliBoard provenance |
| [`LICENSES.md`](LICENSES.md) | Component licensing and attribution |

## Contributing And Support

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Use
synthetic content in reports and never publish real plaintext, complete
ciphertext, contact names, fingerprints, Safety Numbers, QR payloads, private
keys, Vault files, or session state.

- Usage and build help: [`SUPPORT.md`](SUPPORT.md)
- Security vulnerabilities: [`SECURITY.md`](SECURITY.md)
- Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

Report unpatched vulnerabilities privately through
[GitHub Security Advisories](https://github.com/bglglzd/CipherBoard/security/advisories/new).

## License And Attribution

CipherBoard is distributed under the GNU General Public License version 3.0.
See [`LICENSE`](LICENSE) and [`LICENSES.md`](LICENSES.md) for complete terms and
component notices.

CipherBoard is based on HeliBoard `v4.0`, pinned to commit
`bd48798b99cccc99704eebf2a9259c02dbd684d5`. Credits and notices for HeliBoard,
OpenBoard, AOSP Keyboard, LineageOS, and other upstream contributors are
preserved in the source and notice files.
