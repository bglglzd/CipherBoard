<p align="center">
  <img src="app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" width="112" height="112" alt="CipherBoard application icon">
</p>

<h1 align="center">CipherBoard</h1>

<p align="center">
  Offline-first encrypted Android keyboard for physically QR-paired messaging.
</p>

<p align="center">
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/ci.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/bglglzd/CipherBoard/actions/workflows/instrumentation.yml"><img src="https://github.com/bglglzd/CipherBoard/actions/workflows/instrumentation.yml/badge.svg" alt="Android instrumentation status"></a>
  <a href="https://github.com/bglglzd/CipherBoard/releases/latest"><img src="https://img.shields.io/github/v/release/bglglzd/CipherBoard?display_name=tag&amp;sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--only-blue" alt="GPL-3.0-only license"></a>
</p>

CipherBoard is an offline-first encrypted text keyboard for Android, designed
primarily for current GrapheneOS devices. It combines a HeliBoard-based input
method with local identities, physical QR pairing, a protected composer, and a
protected message viewer.

CipherBoard is an unofficial modified fork of HeliBoard. It is not an official
HeliBoard release and is not endorsed or supported by the HeliBoard project.

> [!WARNING]
> CipherBoard is pre-1.0 security-sensitive software. It uses reviewed
> cryptographic primitives and has automated test coverage, but the complete
> product has not received an independent applied-cryptography and Android
> security audit. Do not treat it as audited or risk-free.

[English](#what-it-does) | [Русский](#кратко-по-русски)

| Project fact | Current value |
| --- | --- |
| Maturity | Pre-1.0; current version `0.1.0` |
| Application ID | `org.cipherboard.securekeyboard` |
| Android baseline | `minSdk 23`, `targetSdk 36`; acceptance target is current GrapheneOS |
| Release ABI | `arm64-v8a`; debug builds also include `x86_64` for emulators |
| Runtime network | No Internet or network-state permission; no runtime network feature |
| Interface languages | English and Russian |

## What It Does

Two people can install the same APK and exchange encrypted text without
accounts, phone numbers, email addresses, or a CipherBoard server:

1. Each device creates a local cryptographic identity inside an authenticated
   Vault.
2. The devices pair in person by scanning an offer QR code and a response QR
   code.
3. Both people compare the same Safety Number before marking the contact as
   verified.
4. The sender opens the shield action in the keyboard and writes in the
   CipherBoard-owned Secure Composer.
5. CipherBoard advances and durably stores the Olm ratchet, then commits only a
   `CB1:` ciphertext envelope to the external app.
6. The recipient selects the ciphertext and uses **Decrypt in CipherBoard**.
   Plaintext is displayed in a protected, read-only CipherBoard window and is
   not returned to the transport app.

The transport can be SMS, email, a messenger, or any other application that
can carry text. CipherBoard does not send messages itself.

## Security Boundary

### Implemented controls

- No `android.permission.INTERNET`, network client, Firebase, Google Play
  Services, analytics, advertising, or crash-reporting SDK is part of the
  runtime design.
- Pairing is local and serverless. Version 1 supports physical two-way QR
  pairing only.
- The cryptographic core uses pinned `vodozemac 0.10.0` Olm sessions with the
  version 2 session configuration. CipherBoard does not implement Curve25519,
  Ed25519, AEAD, or the Double Ratchet primitives itself.
- Ratchet state, replay state, and pending operations are transactionally
  committed before ciphertext leaves the IME or plaintext is displayed.
- Vault records are encrypted with a random data-encryption key wrapped by a
  non-exportable, hardware-backed Android Keystore key. StrongBox is attempted
  first; a verified TEE-backed key is the fallback. Software-only keys are not
  accepted.
- Android backup and device-transfer extraction are disabled for application
  data.
- Secure Composer disables personalized learning, suggestions, clipboard
  history, copy/cut/paste actions, autofill, saved view state, and content
  capture. It never commits plaintext through the host `InputConnection`.
- The protected viewer uses `FLAG_SECURE`, disables plaintext selection and
  sharing, clears on backgrounding, and does not return plaintext through
  `ACTION_PROCESS_TEXT`.
- Transport and QR parsers have explicit size/count limits and reject malformed,
  duplicate, non-canonical, inconsistent, or trailing data.

### What it does not solve

CipherBoard cannot fully protect messages when the unlocked device, operating
system, installed APK, or accessibility environment is compromised. It also
cannot prevent a camera or nearby person from seeing the screen, hide transport
metadata, resist physical coercion, or eliminate implementation and dependency
defects. `FLAG_SECURE` and best-effort memory clearing are useful controls, not
absolute guarantees.

The normal keyboard mode retains HeliBoard behavior and may use learning or
clipboard features according to its ordinary settings. The stricter controls
above apply to Secure Composer and the protected viewer.

Read the complete [threat model](THREAT_MODEL.md),
[protocol specification](CRYPTO_PROTOCOL.md), and current
[security review status](SECURITY_REVIEW.md) before evaluating the application
for sensitive use.

## Quick Start

### 1. Obtain and verify an APK

Use only a release published by this CipherBoard repository or build from a
reviewed source commit. Do not install an APK linked from the upstream HeliBoard
project and assume it is CipherBoard.

Verify the release checksum before installation:

```sh
sha256sum --check CipherBoard-0.1.0-release.apk.sha256
```

On Windows PowerShell:

```powershell
(Get-FileHash .\CipherBoard-0.1.0-release.apk -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\CipherBoard-0.1.0-release.apk.sha256
```

If Android Build Tools are installed, also verify the APK signature and compare
the reported SHA-256 certificate digest with
[`SIGNING_CERTIFICATE_SHA256`](SIGNING_CERTIFICATE_SHA256). Obtain the expected
digest through a channel you trust independently of the APK download.

```sh
apksigner verify --verbose --print-certs CipherBoard-0.1.0-release.apk
```

Install or update the verified APK:

```sh
adb install -r CipherBoard-0.1.0-release.apk
```

Debug APKs are developer artifacts signed with a public debug key. Do not use
them for real secrets.

### 2. Enable CipherBoard

On GrapheneOS, open **Settings > System > Keyboard > On-screen keyboard >
Manage on-screen keyboards** and enable CipherBoard. Menu wording can differ
slightly between Android releases.

In **Settings > Apps > CipherBoard**, keep Network denied as defense in depth,
deny Sensors if your OS exposes that permission and it is not needed, and grant
Camera only when you intentionally start QR scanning. CipherBoard does not need
Contacts, SMS, or storage access.

### 3. Create an identity and pair

1. Open CipherBoard and choose a local owner name. The name is not the
   cryptographic identity and is not shared during pairing.
2. Unlock the Vault with a strong device credential or strong biometric.
3. On device A, add a contact, enter a local label, and show the offer QR.
4. On device B, add a contact, scan the offer, enter a local label, and show the
   response QR.
5. On device A, scan the response.
6. Compare the full Safety Number on both devices in person. Mark the contact
   verified only when every group matches.

If either identity changes, stop using the old session and pair again. Never
silently accept a changed key.

### 4. Send and decrypt

To send, focus the destination text field, open CipherBoard, tap the shield,
choose a verified contact, write the message, and tap **Encrypt**. Confirm the
action that inserts the resulting ciphertext. The host field must receive only
text beginning with `CB1:`.

To receive, select all ciphertext parts in the transport app and choose
**Decrypt in CipherBoard** from Android's text actions. Confirm decryption,
unlock the Vault, and read the result in the protected viewer. Ciphertext may be
copied as a fallback; plaintext is never copied automatically.

By default CipherBoard does not keep plaintext history or message keys for
convenient re-reading. A previously viewed message may therefore be impossible
to decrypt again after its temporary local display record is removed.

## Кратко по-русски

CipherBoard - офлайн-клавиатура для обмена зашифрованным текстом без аккаунтов,
телефонных номеров и сервера CipherBoard. Обычный режим основан на HeliBoard. В
защищённом режиме открытый текст вводится в собственном редакторе CipherBoard,
а внешнему приложению передаётся только шифротекст `CB1:`.

Для начала:

1. Установите только проверенный release APK из этого репозитория и сверьте
   SHA-256 и fingerprint сертификата подписи.
2. Включите CipherBoard в системных настройках клавиатур. На GrapheneOS
   дополнительно запретите приложению Network.
3. Создайте локальную identity и разблокируйте Vault.
4. Выполните взаимное физическое QR-сопряжение двух устройств.
5. Полностью сравните Safety Number на обоих экранах и только после этого
   подтвердите контакт.
6. Для отправки нажмите кнопку со щитом, выберите контакт, введите сообщение и
   зашифруйте его. Во внешнем поле должен появиться только `CB1:`-шифротекст.
7. Для чтения выделите шифротекст и выберите **Расшифровать в CipherBoard**.

Приложение не считается независимо аудированным. Оно не защищает от полного
компрометационного доступа к разблокированному устройству, вредоносной
Accessibility-службы, подменённого APK, съёмки экрана камерой, анализа
метаданных транспорта или физического принуждения. Перед использованием в
ситуации высокого риска прочитайте [модель угроз](THREAT_MODEL.md) и
[текущий отчёт о проверках](SECURITY_REVIEW.md).

## Build From Source

The full, pinned environment and release procedure are documented in
[`BUILD.md`](BUILD.md) and [`RELEASE.md`](RELEASE.md). The short debug path is:

```sh
./scripts/build-debug.sh
```

On Windows PowerShell:

```powershell
.\scripts\build-debug.ps1
```

The scripts run source-policy checks, Android lint, module unit tests, build the
APK, and verify its manifest policy. A production release additionally requires
a clean worktree, external signing material, Rust checks, Android device tests,
an offline vulnerability database, and exact APK verification. Never commit a
keystore, signing password, private key, production identity, QR payload, or
session state.

## Repository Map

| Path | Responsibility |
| --- | --- |
| `app/` | HeliBoard-based IME, onboarding, contacts, composer, viewer, and Android integration |
| `crypto-core/` | Minimal Kotlin/JNI boundary and Rust `vodozemac` protocol core |
| `secure-storage/` | Keystore key management, encrypted records, replay state, and atomic operations |
| `pairing/` | Offline pairing state machine and local QR integration |
| `scripts/` | Reproducible build, signing, APK policy, SBOM, and security checks |

Architecture and review documents:

- [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) - scope and product invariants
- [`ARCHITECTURE.md`](ARCHITECTURE.md) - components and trust boundaries
- [`CRYPTO_PROTOCOL.md`](CRYPTO_PROTOCOL.md) - wire and state protocol
- [`THREAT_MODEL.md`](THREAT_MODEL.md) - threats, assumptions, and limitations
- [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md) - requirement traceability
- [`TEST_PLAN.md`](TEST_PLAN.md) - test matrix and acceptance evidence
- [`UPSTREAM.md`](UPSTREAM.md) - exact HeliBoard provenance
- [`LICENSES.md`](LICENSES.md) and
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) - licensing inventory

## Contributing, Support, and Security Reports

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Bug
reports must use synthetic content and must not include real plaintext,
ciphertext, contact names, full fingerprints, Safety Numbers, QR payloads,
private keys, or session state.

- General usage and build help: [`SUPPORT.md`](SUPPORT.md)
- Security vulnerabilities: [`SECURITY.md`](SECURITY.md)
- Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

Security reports are accepted in English or Russian. Do not disclose an
unpatched vulnerability in a public issue.

## License and Upstream Attribution

CipherBoard is distributed under the GNU General Public License version 3.0.
See [`LICENSE`](LICENSE) for the license text and [`LICENSES.md`](LICENSES.md)
for component-specific notices. Distributors of modified binaries must satisfy
the GPL corresponding-source and notice requirements.

CipherBoard is based on HeliBoard `v4.0`, pinned to commit
`bd48798b99cccc99704eebf2a9259c02dbd684d5`. The exact provenance and the
limitations of the unsigned upstream tag are documented in
[`UPSTREAM.md`](UPSTREAM.md). Credits and notices for HeliBoard, OpenBoard, AOSP
Keyboard, LineageOS, and other upstream contributors are preserved in the
source and notice files.
