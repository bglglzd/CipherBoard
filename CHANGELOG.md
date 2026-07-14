# Changelog

All notable CipherBoard changes are documented in this file. The project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from version 0.1.0.
Pre-1.0 releases may contain compatibility changes that require re-pairing.

## [0.3.0] - 2026-07-14

### Added

- An **Encrypt / Decrypt** mode selector inside the shield panel. The primary
  receive flow is now: copy a complete `CB1:` message from any transport, open
  the shield panel, select **Decrypt**, and tap **Paste and decrypt**.
- Embedded, drawing-only plaintext display inside the `FLAG_SECURE` IME window.
- Obscured-touch filtering across the embedded secure panel to reject overlay
  tapjacking attempts on encryption, decryption, reply and Vault actions.
  The surface is non-focusable and non-selectable and is excluded from
  Accessibility text, autofill, content capture, and saved state.
- **Reply securely** in the embedded decrypt view. It clears the received
  plaintext, returns to **Encrypt**, and selects the same local contact without
  placing a contact identifier or plaintext in an Intent.
- A process-local one-shot token handoff for the non-exported Vault unlock
  activity. The handoff must activate and complete exactly once before the IME
  accepts the narrowly scoped host-connection rebind.
- First-draw acknowledgement for pending displays. The encrypted recovery
  record is marked displayed only after an allowed plaintext draw; a bounded
  render timeout fails closed if that acknowledgement never occurs.
- Race-safe ownership for parser/decrypt worker results. Lifecycle cancellation
  drains queued results and wipes any plaintext before removing callbacks.

### Changed

- Clipboard access is explicit and ciphertext-only. CipherBoard reads exactly
  one bounded item after **Paste and decrypt**, validates it as `CB1:`, and
  leaves the original ciphertext clip unchanged.
- Ordinary keyboard keys are hidden in **Decrypt** mode. This prevents the
  receive surface from looking editable and removes an accidental host-input
  affordance while plaintext is visible.
- The embedded panel uses constrained landscape and large-font layouts, a
  scrollable plaintext region, and bounded text lines. Release QA now includes
  portrait/landscape checks at font scales 1.0, 1.3, and 2.0 in English and
  Russian.
- `ACTION_PROCESS_TEXT` and the separate protected viewer remain supported as
  an alternative where the transport exposes Android text actions; they are no
  longer required for the common copied-ciphertext flow.
- The protected Activity viewer now cancels in-flight parsing/decryption on
  background and rechecks the current Vault lock policy immediately before its
  first plaintext draw.
- Android 6-10 device-credential confirmation keeps its non-exported unlock
  host alive only for the controlled system credential transition.

### Security Notes

- Only ciphertext may remain in Android's clipboard. CipherBoard never writes
  decrypted plaintext there, but the transport and clipboard provider can
  still observe or retain the copied ciphertext.
- Ratchet, replay marker, and encrypted pending-display plaintext are committed
  before the embedded surface receives plaintext. Abandoning before first draw
  preserves the encrypted pending display for exact recovery; closing after an
  acknowledged draw removes it under the no-history policy.
- **Reply securely** wipes any hidden outbound draft before selecting the
  decrypted message's contact, preventing a draft from another recipient from
  being reused accidentally.
- Responsive source controls and automated surface tests do not replace visual
  QA on the exact release APK or physical GrapheneOS testing.
- The complete product has not received an independent applied-cryptography or
  Android security audit.

## [0.2.0] - 2026-07-14

### Added

- Embedded Private mode panel above the keyboard keys, opened and closed by the
  shield action without navigating away from the host application.
- A bounded, RAM-only local draft connection for on-screen key input, with
  contact selection, Vault status, transport mode, size estimate, clear, close,
  and encrypt controls inside the IME.
- Exact `InputBinding.connectionToken` scoping for the host field, with one
  explicitly bounded rebind after the Vault unlock activity returns.
- Durable outbound delivery phases. A pending operation changes from `READY` to
  `COMMIT_UNCERTAIN` before host `commitText()` and is never automatically
  retried after the host acknowledgement boundary becomes ambiguous.
- Legacy pending sends from `0.1.x` migrate as `COMMIT_UNCERTAIN`, because the
  old record format cannot prove whether the host already accepted them.

### Changed

- Private plaintext remains visible in the embedded panel after ciphertext was
  inserted, allowing the sender to check it. It is cleared on explicit clear or
  close, when the host field changes, or when the secure lifecycle ends.
- Software keys, text actions, gestures, and IME edit commands route to the
  local Private draft. Personalized learning and clipboard-history paths remain
  disabled while Private mode is active.
- Inherited detailed HeliBoard input diagnostics are suppressed for the Private
  editor even when debug mode is enabled, so words and n-gram context are not
  written to logcat.
- The IME window uses `FLAG_SECURE` in Private mode. The separate protected
  viewer and read-only `ACTION_PROCESS_TEXT` decryption flow remain activities.
- Stable update guidance continues to use an external installer such as
  Obtainium. CipherBoard has no in-app updater and requests neither Internet nor
  package-install permission.

### Security Notes

- Android can deliver a physical keyboard directly to the focused host
  application. Hardware keyboards must not be used to enter a Private draft;
  use CipherBoard's on-screen keys.
- Mutable buffers and UI text are wiped on a best-effort basis. Android views,
  Binder, JNI, and the JVM may create copies, so complete RAM erasure cannot be
  guaranteed.
- The complete product has not received an independent applied-cryptography or
  Android security audit.

## [0.1.1] - 2026-07-13

### Fixed

- Restored readable text and controls in native CipherBoard screens on Android
  12 and later by making light/dark platform-theme colors explicit across
  resource qualifiers.

### Changed

- Documented stable, install-in-place updates through Obtainium while
  CipherBoard itself remains offline and has no Internet permission.
- Added a GrapheneOS installation and update guide with signing-certificate
  continuity, data-preservation, and Android confirmation guidance.

### Security Notes

- This update does not change the application ID, signing certificate, Vault
  format, or messaging protocol. Install it over `0.1.0`; uninstalling first
  destroys local identity and ratchet state and requires pairing again.
- Obtainium is an external networked installer and a separate trust boundary.
  CipherBoard does not contact GitHub and does not install its own updates.

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

[0.3.0]: https://github.com/bglglzd/CipherBoard/releases/tag/v0.3.0
[0.2.0]: https://github.com/bglglzd/CipherBoard/releases/tag/v0.2.0
[0.1.1]: https://github.com/bglglzd/CipherBoard/releases/tag/v0.1.1
[0.1.0]: https://github.com/bglglzd/CipherBoard/releases/tag/v0.1.0
