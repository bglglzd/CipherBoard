# Changelog

All notable CipherBoard changes are documented in this file. The project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from version 0.1.0.
Pre-1.0 releases may contain compatibility changes that require re-pairing.

## [0.1.0] - 2026-07-13

### Added

- HeliBoard-based Android IME with English, Russian, emoji, symbols, themes,
  layouts, and ordinary keyboard settings retained.
- Local identities and an authenticated encrypted Vault backed by Android
  Keystore, with StrongBox-first generation and verified TEE fallback.
- Physical two-way QR pairing, local contact names, fingerprints, Safety
  Numbers, explicit verification, key-change handling, and re-pairing.
- Pinned `vodozemac 0.10.0` Olm version 2 sessions, bounded replay state,
  canonical `CB1:` envelopes, multipart transport, and crash-safe ratchet
  transactions.
- Secure Composer that keeps plaintext out of the host editor and commits only
  ciphertext after an explicit user action.
- Read-only Android `ACTION_PROCESS_TEXT` decryption, selected-ciphertext
  handling from the IME, and a protected viewer with secure reply.
- English and Russian application UI, offline license viewer, threat model,
  security checklist, SBOM generation, vulnerability scanning, and signed APK
  policy gates.

### Security Notes

- CipherBoard has no runtime network feature and the release policy rejects
  `android.permission.INTERNET` and other forbidden permissions.
- Plaintext history is disabled by default; message keys are not retained for
  convenient re-reading.
- The complete product has not received an independent applied-cryptography or
  Android security audit. Physical GrapheneOS, StrongBox, TEE-only, live-camera
  pairing, and hostile-device validation remain necessary before high-risk use.

[0.1.0]: https://github.com/bglglzd/CipherBoard/releases/tag/v0.1.0
