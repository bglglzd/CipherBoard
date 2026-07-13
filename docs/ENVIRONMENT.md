# Development Environment

This document records the read-only environment audit performed on 2026-07-13
before CipherBoard development started. Paths and versions are specific to the
audited Windows workstation. No credentials, signing material, or other secrets
are recorded here.

## Repository Context

- Working directory: `<workspace>\cipherboard`
- Upstream repository: `https://github.com/HeliBorg/HeliBoard.git`
- Upstream tag: `v4.0`
- Upstream commit: `bd48798b99cccc99704eebf2a9259c02dbd684d5`
- Development branch: `feature/secure-messaging-keyboard`
- Git version: `2.53.0.windows.1` (`x86_64`)
- Git global `core.longpaths`: unset
- Git global `core.autocrlf`: unset
- Windows `LongPathsEnabled`: `0`
- `local.properties` points Gradle at the installed Android SDK and is not
  intended for source control.

The initial audit found an empty, uninitialized directory. The official
HeliBoard repository was subsequently checked out at `v4.0`, and the branch
listed above was created before this document was added.

## Host System

- OS: Microsoft Windows 11 Pro, 64-bit
- OS version/build: `10.0.26200` / `26200`
- PowerShell: `7.6.3` Core (`Win32NT`)
- Physical memory: `34,122,719,232` bytes (approximately 31.8 GiB)
- Free space on `C:` at audit time: `149,772,173,312` bytes
  (approximately 139.5 GiB)

## Java and Gradle

The default Java environment is not suitable for compilation:

- `JAVA_HOME`: `C:\Program Files\Eclipse Adoptium\jre-17.0.8.101-hotspot\`
- Default Java: Temurin `17.0.8.1+1`
- Default `javac`: missing
- Global Gradle command: missing

A complete JDK is bundled with Android Studio:

- JBR/JDK path: `C:\Program Files\Android\Android Studio\jbr`
- Java: OpenJDK `21.0.10` (`21.0.10+-14961533-b1163.108`)
- `javac`: `21.0.10`
- Android Studio build: `AI-261.23567.138.2611.15646644`
- Cached Gradle wrapper distributions: `8.10.2`, `8.14`

Builds should use the repository's Gradle wrapper. Set `JAVA_HOME` for the
build session to the Android Studio JBR only after confirming compatibility
with the checked-in wrapper. If that wrapper does not support JDK 21, install
or select a complete JDK 17 rather than using the current JRE-only installation.

## Android SDK

- SDK root: `%LOCALAPPDATA%\Android\Sdk`
- `ANDROID_HOME`: unset during the audit
- `ANDROID_SDK_ROOT`: unset during the audit
- Installed platforms:
  - Android API 35, platform revision 2, extension level 13
  - Android API 36.1, platform revision 1, extension level 20
- Installed build-tools: `34.0.0`, `36.1.0`, `37.0.0`
- Platform-tools: `37.0.0`
- ADB: `1.0.41`, build `37.0.0-14910828`
- AAPT from build-tools 37.0.0: build `15087165`
- AAPT2 from build-tools 37.0.0: `2.20-15087165`
- APK Signer from build-tools 37.0.0: `0.9`
- `zipalign`: present in build-tools 37.0.0
- ADB server: not running at audit time

`aapt`, `aapt2`, `apksigner`, and `zipalign` are installed under the SDK but
were not on `PATH`. The SDK Command-line Tools package was not installed, so
`sdkmanager`, `avdmanager`, and `apkanalyzer` were unavailable.

## Android Emulator

- Emulator: `36.6.11.0`, build `15507667`
- Configured AVD: `Pixel_10`
- Installed system image:
  `android-37.0/google_apis_playstore_ps16k/x86_64`

The only installed image includes the Google Play Store. It is not sufficient
as the sole acceptance environment for the requirement to run without Google
Play. Add an AOSP/non-Play `x86_64` image for connected and no-Play testing.

## Native Toolchain

- Android NDK: `27.0.12077973` (`r27`)
- NDK path:
  `%LOCALAPPDATA%\Android\Sdk\ndk\27.0.12077973`
- NDK API 21 compiler wrappers: present for `aarch64-linux-android` and
  `x86_64-linux-android`
- Android SDK CMake: `3.22.1-g37088a8-dirty`
- CMake path:
  `%LOCALAPPDATA%\Android\Sdk\cmake\3.22.1`
- Ninja on `PATH`: `1.13.0.git.kitware.jobserver-pipe-1`
- Visual Studio Build Tools 2022: `17.14.28` / `17.14.37027.9`
- MSVC tools: `14.44.35207`
- Windows SDK: `10.0.26100.0`

Host `clang`, `clang-cl`, `lld`, and `make` were not on `PATH`. Android NDK
Clang is installed, so a separate host Clang is not required for the Android
native build. MSVC is installed but is exposed through a Visual Studio
developer environment rather than the default `PATH`.

## Rust

- `rustup`: `1.29.0`
- Active toolchain: `stable-x86_64-pc-windows-msvc`
- `rustc`: `1.94.0` (`4a4ef493e`, LLVM `21.1.8`)
- Cargo: `1.94.0` (`85eff7c80`)
- Rustfmt: `1.8.0-stable`
- Clippy: `0.1.94`
- Installed Rust target: `x86_64-pc-windows-msvc` only

Missing Rust components needed by the planned native Android workflow:

- `aarch64-linux-android` target
- `x86_64-linux-android` target
- `cargo-ndk`
- `cargo-audit`
- global `uniffi-bindgen` command

Pin tool versions in the project before installing them. UniFFI tooling may be
kept as a pinned project dependency instead of a global executable.

## Shell and Release Utilities

The `bash` command on the default Windows `PATH` resolved to a broken
WindowsApps/WSL alias. A working Git Bash installation is available:

- Git Bash: `C:\Program Files\Git\bin\bash.exe`
- Git Bash version: GNU Bash `5.2.37`
- `sh`: available in the Git installation
- `sha256sum`: available in the Git installation
- OpenSSL: available in the Git installation
- `unzip`: available in the Git installation
- `zip`: missing
- Windows `tar`: available

Windows `.sh` scripts should invoke Git Bash explicitly or prepend the Git
`bin` and `usr\bin` directories for the build session. A separate `zip`
installation is unnecessary unless a project script actually depends on it;
Gradle provides APK packaging.

## Initial Gaps and Required Actions

This list records the state at the initial read-only audit. Java/tool selection,
Android command-line tools, Rust targets/tools, the AOSP no-Play AVD and
connected-test availability were subsequently resolved as described below; it
must not be read as the current environment status.

1. **Java compiler selection:** the active `JAVA_HOME` is a JRE without
   `javac`. Select the Android Studio JBR 21 for compatible Gradle builds, or a
   complete supported JDK 17.
2. **Android Command-line Tools:** install the official latest package to
   provide `sdkmanager`, `avdmanager`, and `apkanalyzer`.
3. **Rust Android targets:** install pinned support for
   `aarch64-linux-android` and `x86_64-linux-android` before native builds.
4. **Cargo Android/security tools:** install a pinned `cargo-ndk` and
   `cargo-audit` when their project versions are selected.
5. **No-Play test environment:** install an AOSP/non-Play `x86_64` emulator
   image or use a suitable physical GrapheneOS device for acceptance testing.
6. **Connected tests:** no device or emulator was running during the audit;
   `connectedCheck` requires one before it can run.
7. **Windows shell selection:** use the explicit Git Bash executable because
   the default `bash` alias is not functional.

The existing Android platforms, build-tools, platform-tools, NDK, CMake,
Android Studio JDK, and MSVC Build Tools do not need replacement. Prefer
session-local or repository-local configuration, and avoid global system
changes unless a verified build problem requires one.

## Post-audit Provisioning

The following narrowly scoped changes were made after the read-only audit to
build the pinned upstream revision:

- `local.properties` was created as a Git-ignored file pointing to the SDK.
- Build sessions select the Android Studio JBR/JDK 21 without changing the
  global `JAVA_HOME`.
- Gradle installed the pinned NDK `28.0.13004108` and Android Platform 36
  revision 2 after verifying the already accepted SDK licenses. Release builds
  are pinned to the already installed Build Tools `36.1.0`.
- Rust targets `aarch64-linux-android` and `x86_64-linux-android` were installed.
- `cargo-ndk 4.1.2` and `cargo-audit 0.22.2` were installed with Cargo's
  `--locked` option.
- `cargo-fuzz 0.13.2` and the Rust nightly MSVC toolchain were installed for
  the bounded libFuzzer/AddressSanitizer transport-parser campaign.
- Official OSV-Scanner `2.4.0` for Windows amd64 was stored outside the
  repository at
  `~/.local/share/cipherboard/tools/osv-scanner/2.4.0/osv-scanner.exe`; its
  official release SHA-256 is enforced by `scripts/osv_offline_scan.py`.
- Official Android SDK Command-line Tools `20.0` (build `15641748`) were
  installed after verifying Google's published SHA-1
  `2bea1388b8a248040a340a08ca0638138633f687`; this provides `sdkmanager`,
  `avdmanager`, and `apkanalyzer`.
- Repository-local Git `core.longpaths=true` was enabled; no global Git or
  Windows registry setting was changed.

The unmodified HeliBoard `v4.0` application assembled successfully with
`:app:assembleDebug`. Its documented `:app:testRunTestsUnitTest` gate initially
exposed a Windows-only Android asset path defect and a nondeterministic external
HTTP link check. CipherBoard changed asset separators to the Android-standard
`/` and made link checks explicitly opt-in through
`CIPHERBOARD_RUN_NETWORK_TESTS=1`; the offline test gate then passed.

The AOSP-only image `system-images;android-36;default;x86_64` revision 2 and AVD
`CipherBoard_API_36_AOSP` were subsequently installed. It contains no Play
Store image and is the default local target for connected no-Play tests. A
physical GrapheneOS device is still required for GrapheneOS-specific behavior,
StrongBox/TEE reporting, and final device acceptance.

The AOSP AVD was started as `emulator-5554`. Native Alice/Bob connected tests
completed on this target. The full app command
`:app:connectedDebugAndroidTest --no-configuration-cache` subsequently passed
7/7 tests with 0 failures and 0 skipped on the same API 36 x86_64 no-Play AVD.
Release lint for `app`, `crypto-core`, `pairing`, and `secure-storage` also
passes after the API 23 compatibility fixes.

The seven connected tests cover process-text returning `RESULT_CANCELED` with no
data and unchanged host text; viewer `FLAG_SECURE`, background display-lease
close and byte/char buffer zeroization; explicit ciphertext-only clipboard
fallback retaining the clip; two real vault close/reopen atomicity cases; and
three debug-only remote `:fault` process cases using actual
`Process.killProcess`/SIGKILL before outbound commit, after outbound commit
before handoff, and after inbound commit. The fault activity/source is excluded
from release builds.

This environment evidence does not cover failure between individual SQLite
statements, an ambiguous kill immediately around acknowledgement from a real
host `InputConnection.commitText()`, full IME/composer/live-camera pairing E2E,
or any physical GrapheneOS, StrongBox, TEE or biometric behavior.

The current debug APK was also installed and its Home activity launched on this
AVD. The English hierarchy had bounded, non-overlapping controls. Applying the
per-app `ru-RU` locale produced complete Russian Home strings, and at
`font_scale=1.3` in landscape every observed Home text/button bound fit without
overlap. A `FLAG_SECURE` test screencap was fully black; this was not a
secure-viewer-specific screenshot acceptance test.

The locale smoke exposed an inherited `SystemBroadcastReceiver` self-SIGKILL
loop when changing locale before CipherBoard had been selected as the IME. After
the fix, rebuild and reinstall, the app process remained alive for the recorded
three-second observation and the Russian hierarchy remained available. Full
ordinary-IME, composer, viewer-screenshot, accessibility and layout-matrix
acceptance remains outstanding.
