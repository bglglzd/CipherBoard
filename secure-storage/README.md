# CipherBoard secure storage

This module owns the credential-protected Vault boundary. It stores the database and wrapped
Vault data-encryption key (DEK) below `noBackupFilesDir`, encrypts every record independently,
and exposes atomic ratchet/pending-operation transactions.

The caller must pass a credential-protected `Context`. The module rejects a
`context.isDeviceProtectedStorage == true` context. Android has a public API to create a
device-protected context but no inverse public API, so an application using
`android:defaultToDeviceProtectedStorage="true"` must remove that default and explicitly give only
the small direct-boot keyboard subset a device-protected context.

The Android platform has two distinct authentication flows:

* a strong-biometric-only, authentication-per-use key can be passed to
  `BiometricPrompt.authenticate(promptInfo, CryptoObject)`;
* a key accepting either `BIOMETRIC_STRONG` or `DEVICE_CREDENTIAL` must use a short
  authentication-validity window and a prompt without `CryptoObject`. Android's official API
  explicitly does not permit a `CryptoObject` in the credential-fallback flow.

`VaultAuthenticationMode` exposes both choices instead of claiming that the platform offers a
combined CryptoObject flow. CipherBoard should default to `BIOMETRIC_OR_DEVICE_CREDENTIAL` so a
strong device credential is usable on Android 11 and newer.

Android 10 and older cannot bind a device credential to an authentication-per-use key. Their only
credential-capable Keystore API grants a time-based authorization window, which does not meet the
new-Vault policy. CipherBoard therefore canonicalizes a new
`BIOMETRIC_OR_DEVICE_CREDENTIAL` request on API 23--29 to
`BIOMETRIC_STRONG_CRYPTO_OBJECT` and generates only a per-use key with validity `-1`. Creating a
Vault on these releases requires an enrolled hardware-backed strong biometric; device-credential
fallback requires Android 11 or newer. A pre-release legacy envelope that already names a
credential-window key can still be opened through the system confirm-credential flow, but this
module never generates another such key.

The module never persists plaintext, raw DEKs, contact names, or ratchet state. Kotlin/JVM and UI
objects can still create copies that cannot be guaranteed to be overwritten; callers must keep
plaintext lifetimes short and call all provided `close`/`lock` APIs.
