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
| JDK | 17 with `javac` |
| compileSdk / targetSdk / minSdk | 36 / 36 / 23 |
| Android NDK | 28.0.13004108 |
| Rust used for verified JNI work | 1.94.0 |
| cargo-ndk used for verified JNI work | 4.1.2 |
| vodozemac | 0.10.0, locked |
| Android ABIs | `arm64-v8a`, `x86_64` |

The Gradle product identity is centralized in `gradle.properties`:

```text
cipherboard.applicationId=org.cipherboard.securekeyboard
cipherboard.productName=CipherBoard
cipherboard.versionCode=10000
cipherboard.versionName=0.1.0
cipherboard.artifactName=CipherBoard
```

Change these values intentionally and review upgrade behavior before release.

## Prerequisites

1. A JDK 17 installation containing `java`, `javac`, and `keytool`.
2. Android SDK platform 36, build-tools, command-line tools and NDK
   `28.0.13004108`.
3. Rust and Cargo with Android targets `aarch64-linux-android` and
   `x86_64-linux-android`.
4. `cargo-ndk 4.1.2`, `cargo-audit`, Python 3, Git, ADB and standard shell
   tools. PowerShell scripts require PowerShell 7.
5. `ANDROID_SDK_ROOT` or `ANDROID_HOME` set to the Android SDK.

On Windows, ensure `JAVA_HOME` points to a JDK rather than a JRE. The Android
Studio runtime can be used when it includes `javac`.

## Dependency Integrity

- Gradle itself is fetched through the wrapper with a pinned distribution
  checksum.
- Cargo direct dependencies use exact versions and both Rust crates have
  checked-in `Cargo.lock` files. Release commands use `--locked` where Cargo
  resolves Android artifacts.
- **Gradle dependency locking is not yet enabled.** Direct dependencies and the
  Compose BOM are versioned, but transitive artifacts are not represented by a
  checked-in lockfile. This is a known reproducibility blocker.

After dependencies have been cached, Gradle may be tested with `--offline`.
This does not change the requirement that the installed application has no
network permission or runtime network behavior.

## Build and Test Commands

From the repository root:

```sh
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug

cargo fmt --all --manifest-path crypto-core/native/Cargo.toml -- --check
cargo clippy --manifest-path crypto-core/native/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock

cargo fmt --all --manifest-path crypto-core/jni/Cargo.toml -- --check
cargo clippy --manifest-path crypto-core/jni/Cargo.toml \
  --all-targets --all-features -- -D warnings
cargo test --manifest-path crypto-core/jni/Cargo.toml
cargo audit --file crypto-core/jni/Cargo.lock
```

Run Android JNI instrumentation on an emulator or device:

```sh
./gradlew :crypto-core:connectedDebugAndroidTest
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

`build-debug` runs lint, unit tests, builds the APK, copies it to `dist/`, and
applies the APK policy verifier. `build-release` additionally runs Rust checks,
requires external signing material, signs with `apksigner`, and writes the APK
SHA-256, CycloneDX `SBOM.json`, `BUILD_INFO.txt`, and notices. Neither release
script creates or overwrites a keystore.

## APK Verification Policy

The verifier requires `aapt`, `apkanalyzer`, `apksigner`, `zipalign` and
Python 3. It fails closed on:

- forbidden network, contacts, SMS, overlay, package-query or accessibility
  permissions;
- `allowBackup` or cleartext traffic, and release `debuggable`/`testOnly`;
- unapproved exported components or network deep links;
- Firebase, Google Play Services, analytics, crash-reporting, advertising,
  WebView or dynamic-code-loader markers in executable APK entries;
- missing v2 signature, failed signature validation, bad ZIP alignment, or an
  Android debug certificate on a release APK.

The policy is a release gate, not a substitute for manual intent-validation,
native hardening, and source review.

## Current Status

The crypto and JNI modules build and their automated tests pass, including an
Android Alice/Bob JNI smoke test. The overall application is still under active
integration. See `SECURITY_REVIEW.md`; do not interpret successful module
builds as a production release approval or independent audit.
