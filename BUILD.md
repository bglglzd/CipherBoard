# Building CipherBoard

CipherBoard is built from source as an Android application with Kotlin/Java,
the inherited HeliBoard C++ dictionary engine, and a Rust JNI crypto library.
Runtime operation is offline and the release manifest must not request
`android.permission.INTERNET`. Network access may be needed only to populate
development dependency caches.

## Pinned Build Baseline

| Tool or input | Version |
| --- | --- |
| HeliBoard upstream | `v4.0`, `bd48798b99cccc99704eebf2a9259c02dbd684d5` |
| Gradle wrapper | 8.14; distribution SHA-256 pinned in wrapper properties |
| Android Gradle Plugin | 8.13.2 |
| Kotlin | 2.3.20 |
| JDK | 21 with `javac` (application bytecode remains Java 17 compatible) |
| Android build-tools | 36.1.0 |
| compileSdk / targetSdk / minSdk | 36 / 36 / 23 |
| Android NDK | 28.0.13004108 |
| Rust used for verified JNI work | 1.94.0 |
| cargo-ndk used for verified JNI work | 4.1.2 |
| vodozemac | 0.10.0, locked |
| Android ABIs | release `arm64-v8a`; debug/test `arm64-v8a`, `x86_64` |

The Gradle product identity is centralized in `gradle.properties`:

```text
cipherboard.applicationId=org.cipherboard.securekeyboard
cipherboard.productName=CipherBoard
cipherboard.versionCode=40002
cipherboard.versionName=0.4.2
cipherboard.artifactName=CipherBoard
```

Change these values intentionally and review upgrade behavior before release.

## Prerequisites

1. A JDK 21 installation containing `java`, `javac`, and `keytool`.
2. Android SDK platform 36, Build Tools `36.1.0`, command-line tools and NDK
   `28.0.13004108`.
3. Rust and Cargo with Android targets `aarch64-linux-android` and
   `x86_64-linux-android`.
4. `cargo-ndk 4.1.2`, `cargo-audit`, Python 3, Git, ADB and standard shell
   tools. PowerShell scripts require PowerShell 7.
5. `ANDROID_SDK_ROOT` or `ANDROID_HOME` set to the Android SDK.
6. For release, official OSV-Scanner v2.4.0 plus local Maven and crates.io
   `all.zip` databases no more than seven days old. The script verifies the
   scanner against its pinned platform SHA-256 and runs it offline.

Set `CIPHERBOARD_OSV_SCANNER` to the verified executable when it is not on
`PATH`. Refresh only the public advisory databases before entering the offline
release step:

```text
osv-scanner scan source --offline --offline-vulnerabilities --download-offline-databases --allow-no-lockfiles <empty-directory>
```

On Windows, ensure `JAVA_HOME` points to a JDK rather than a JRE. The Android
Studio runtime can be used when it includes `javac`.

## Dependency Integrity

- Gradle itself is fetched through the wrapper with a pinned distribution
  checksum.
- Cargo direct dependencies use exact versions and both Rust crates have
  checked-in `Cargo.lock` files. Release commands use `--locked` where Cargo
  resolves Android artifacts.
- The packageable `:app` dependency graphs use strict Gradle dependency
  locking. Their resolved versions are committed in `app/gradle.lockfile`.
  When an intentional dependency change is made, regenerate and review that
  file with:

```sh
./gradlew :app:resolveApplicationDependencyLocks --write-locks --no-configuration-cache
```

Do not refresh locks incidentally during an unrelated change. Review both the
lockfile diff and regenerated SBOM before accepting an upgrade.

After dependencies have been cached, Gradle may be tested with `--offline`.
This does not change the requirement that the installed application has no
network permission or runtime network behavior.

## Build and Test Commands

From the repository root:

```sh
./gradlew :app:lintDebug :app:testDebugUnitTest \
  :crypto-core:testDebugUnitTest :pairing:testDebugUnitTest \
  :secure-storage:testDebugUnitTest :app:assembleDebug

./gradlew :app:lintRelease :crypto-core:lintRelease \
  :pairing:lintRelease :secure-storage:lintRelease

cargo fmt --all --manifest-path crypto-core/native/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/native/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock

cargo fmt --all --manifest-path crypto-core/jni/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/jni/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/jni/Cargo.toml
cargo audit --file crypto-core/jni/Cargo.lock
```

The production transport parser has a separate pinned cargo-fuzz package. From
`crypto-core/native`, run a bounded sanitizer campaign with:

```sh
cargo +nightly fuzz run transport_parser fuzz/corpus/transport_parser -- \
  -max_total_time=60 -max_len=393216 -timeout=5
```

See `crypto-core/native/fuzz/README.md` for pinned prerequisites and the Windows
AddressSanitizer runtime setup. Fuzz dependencies are development-only and are
not packaged in the APK.

Run Android JNI instrumentation on an emulator or device:

```sh
./gradlew :crypto-core:connectedDebugAndroidTest
./gradlew :app:connectedDebugAndroidTest --no-configuration-cache
```

The Android library build invokes cargo-ndk for both supported ABIs and
packages only `libcipherboard_crypto_jni.so`; generated native libraries remain
under `build/` and are not committed.

## Convenience Scripts

Unix-like shell:

```sh
scripts/build-debug.sh
scripts/build-release.sh
scripts/verify-apk.sh [--debug] path/to/app.apk
```

PowerShell 7:

```powershell
./scripts/build-debug.ps1
./scripts/build-release.ps1
./scripts/verify-apk.ps1 [-DebugBuild] path/to/app.apk
```

`build-debug` runs the fork-wide source/security and Kotlin-format gates,
`lintDebug`, full app/library debug unit tasks, builds the APK, copies it to
`dist/`, and applies the APK policy verifier. Two inherited HeliBoard regression
tests are explicitly `@Ignore`d with issue-specific reasons; no build type
conditionally bypasses these two tests. `build-release` additionally runs all
module release lint tasks, Rust format/Clippy/test/audit with locked graphs, requires
external signing material, signs with `apksigner`, and writes the APK SHA-256,
CycloneDX `SBOM.json`, offline `VULNERABILITY_SCAN.json`,
`RELEASE_ARTIFACTS.sha256`, `BUILD_INFO.txt`, notices, and an exact-commit GPL
source archive. It accepts only an official OSV-Scanner v2.4.0 binary with a
pinned SHA-256, requires fresh local Maven/crates.io databases, scans without
network access, and fails on a finding or package-count mismatch. It rechecks
the same clean Git HEAD before signing and publication.
Neither release script creates or overwrites a keystore.

The APK includes complete local license/provenance texts as generated assets;
the non-exported license activity reads only those packaged files and performs
no network lookup.

## APK Verification Policy

The verifier requires `aapt`, `apkanalyzer`, `apksigner`, `zipalign` and
Python 3. It fails closed on:

- forbidden network, contacts, SMS, overlay, package-query or accessibility
  permissions;
- `allowBackup` or cleartext traffic, and release `debuggable`/`testOnly`;
- unapproved exported components or network deep links;
- Firebase, Google Play Services, analytics, crash-reporting, advertising,
  WebView or dynamic-code-loader markers in executable APK entries;
- missing v2 signature, failed signature validation, bad ZIP alignment, an
  Android debug certificate, or a signer that does not match the reviewed
  public `SIGNING_CERTIFICATE_SHA256` pin on a release APK.

The policy is a release gate, not a substitute for manual intent-validation,
native hardening, and source review.

## Current Status

On the current 2026-07-14 worktree, the complete app/library debug unit tasks and
release lint gates for all four modules pass after the API 23 compatibility
fixes. The Rust native suite reports 43 passing tests and the narrow JNI crate
reports 3; Rust format, Clippy and dependency audit gates also pass. These
results include deterministic CBOR, compact/word presentation and legacy
multipart compatibility regressions, storage transactions, contact-bound
pending operations, pairing cleanup/key-change behavior, and the typed
one-shot IME handoff.

The production envelope/presentation parser also completed a 61-second
ASan/libFuzzer run: 236,453 inputs, zero crashes, zero timeouts and zero
artifacts, using nine reviewed seeds and `max_len=393216`. This bounded campaign does not
replace longer scheduled fuzzing or future pairing/JNI targets. Release
preflight also scanned all 255 CycloneDX packages using the pinned official
OSV-Scanner v2.4.0 and fresh offline Maven/crates.io databases; it exited zero
with no findings. A clean pre-public local signed-candidate pipeline subsequently
repeated the gate, signed the APK with the pinned non-debug release certificate,
ran the APK policy verifier, and generated a local evidence bundle. That bundle
is not tracked or published and must not be treated as evidence for the rewritten
public history. The final public tag must run the complete pipeline again and
publish its own `BUILD_INFO.txt`, hash manifest, and other release assets.

On the API 36 x86_64 `CipherBoard_API_36_AOSP` no-Play emulator,
`:app:connectedDebugAndroidTest --no-configuration-cache` passes 7/7 tests with
zero failures/skips. The scope covers read-only process-text behavior, viewer
`FLAG_SECURE` and background byte/char wiping, ciphertext clipboard retention,
two vault close/reopen atomicity tests, and three actual remote-process SIGKILL
boundaries: before outbound commit, after outbound commit/before handoff, and
after inbound commit. The remote `:fault` activity/fixture is debug-only and is
not packaged in release.

This run does not inject failure between individual SQLite statements, kill in
the ambiguous instant around a real host `InputConnection.commitText()`
acknowledgement, or exercise a complete IME/composer/live-camera pairing flow.
No physical GrapheneOS, StrongBox, TEE-fallback, biometric, secure-viewer
screenshot or two-camera result is claimed.

The same debug APK installs and launches Home on the AOSP emulator. English and
per-app `ru-RU` Home controls are bounded and non-overlapping; Russian landscape
also fits at `font_scale=1.3`. A `FLAG_SECURE` test capture is fully black, but
is not a secure-viewer screenshot test. After fixing an inherited
`SystemBroadcastReceiver` self-SIGKILL loop on locale change before IME
selection, the rebuilt process remained alive for the recorded three-second
observation and exposed the Russian hierarchy. This smoke check is not ordinary
IME input or full layout/accessibility coverage.

A pre-public local signed candidate exists, but this document does not claim
that candidate as the final published release or as evidence for the rewritten
public history. No physical-device or GrapheneOS acceptance result is claimed.
See `SECURITY_REVIEW.md`; passing automated and artifact gates is neither
independent audit evidence nor approval for high-risk use.
