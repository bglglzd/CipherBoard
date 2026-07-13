# Upstream HeliBoard

CipherBoard is an unofficial modified fork of HeliBoard. It is not an official
HeliBoard release and is not endorsed, supported, or distributed by the
HeliBoard project. CipherBoard uses its own application name, package name, and
branding so that it cannot be mistaken for an upstream build.

## Pinned Upstream Revision

The upstream source is the official HeliBoard repository:

- Repository: <https://github.com/HeliBorg/HeliBoard>
- Stable release: `HeliBoard 4.0`
- Tag: `v4.0`
- Commit: `bd48798b99cccc99704eebf2a9259c02dbd684d5`
- Commit timestamp: `2026-07-10T13:29:55Z`
- Release publication timestamp: `2026-07-10T13:44:02Z`
- Release status when checked on 2026-07-13: published, not a draft, and not a
  prerelease

Primary upstream references:

- Release: <https://github.com/HeliBorg/HeliBoard/releases/tag/v4.0>
- Release API record:
  <https://api.github.com/repos/HeliBorg/HeliBoard/releases/tags/v4.0>
- Commit:
  <https://github.com/HeliBorg/HeliBoard/commit/bd48798b99cccc99704eebf2a9259c02dbd684d5>
- Source tree pinned by commit:
  <https://github.com/HeliBorg/HeliBoard/tree/bd48798b99cccc99704eebf2a9259c02dbd684d5>

The `v4.0` reference is a lightweight tag that directly resolves to the commit
above. The pinned commit is unsigned: GitHub reports `verified=false` with the
reason `unsigned`. Consequently, the tag does not provide cryptographic
provenance. The full commit hash is recorded to make the selected source exact,
but this must not be described as verification by a signed upstream release.

The revision can be checked without relying on the current upstream branch:

```sh
git ls-remote --tags https://github.com/HeliBorg/HeliBoard.git refs/tags/v4.0
```

The expected output starts with:

```text
bd48798b99cccc99704eebf2a9259c02dbd684d5
```

## Upstream Build Baseline

The following values come from the pinned `v4.0` build files and workflows:

| Component | Upstream value |
| --- | --- |
| Gradle wrapper | `8.14` |
| Gradle distribution SHA-256 | `61ad310d3c7d3e5da131b76bbf22b5a4c0786e9d892dae8c1658d4b484de3caa` |
| Android Gradle Plugin | `8.13.2` |
| Kotlin | `2.3.20` |
| Application Java/Kotlin target | Java 17 / JVM 17 |
| Official CI JDK | Temurin 17 |
| `compileSdk` | `36` |
| `targetSdk` | `36` |
| `minSdk` | `21` |
| Android NDK | `28.0.13004108` |
| Native build system | `ndk-build` using `app/src/main/jni/Android.mk` |
| Upstream application ABIs | `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64` |

The optional `:tools:make-emoji-keys` JVM utility targets Java 21. It is not
part of the normal upstream `assembleDebug` application workflow. Upstream does
not use CMake for the application native code.

The upstream Gradle modules are:

```text
:app
:tools:make-emoji-keys
```

Relevant pinned build files:

- <https://github.com/HeliBorg/HeliBoard/blob/v4.0/build.gradle.kts>
- <https://github.com/HeliBorg/HeliBoard/blob/v4.0/app/build.gradle.kts>
- <https://github.com/HeliBorg/HeliBoard/blob/v4.0/gradle/wrapper/gradle-wrapper.properties>
- <https://github.com/HeliBorg/HeliBoard/blob/v4.0/.github/workflows/build-debug-apk.yml>
- <https://github.com/HeliBorg/HeliBoard/blob/v4.0/.github/workflows/build-test-auto.yml>

The upstream CI build and unit-test entry points are:

```sh
./gradlew assembleDebug
./gradlew testRunTestsUnitTest
```

## Licensing and Attribution

HeliBoard states that the project, as a fork of OpenBoard, is licensed under the
GNU General Public License version 3. The repository also contains code derived
from the Apache-2.0-licensed AOSP Keyboard and an upstream icon licensed under
Creative Commons Attribution-ShareAlike 4.0.

CipherBoard distributions and corresponding source must preserve all applicable
copyright and license notices. In particular:

- retain the GNU GPL v3 license and comply with its complete corresponding
  source requirements for the modified work;
- retain the Apache License 2.0 text and copyright headers for inherited AOSP
  portions;
- retain the CC BY-SA 4.0 license and attribution for any inherited icon or
  artwork that remains in the source or distributed artifacts;
- preserve relevant credits for HeliBoard, OpenBoard, AOSP Keyboard, LineageOS,
  and other credited upstream contributors;
- mark CipherBoard changes as modifications and never present CipherBoard as an
  official HeliBoard release.

The authoritative upstream license and attribution files are:

- GPL v3: <https://github.com/HeliBorg/HeliBoard/blob/v4.0/LICENSE>
- Apache 2.0:
  <https://github.com/HeliBorg/HeliBoard/blob/v4.0/LICENSE-Apache-2.0>
- CC BY-SA 4.0:
  <https://github.com/HeliBorg/HeliBoard/blob/v4.0/LICENSE-CC-BY-SA-4.0>
- Upstream license statement and credits:
  <https://github.com/HeliBorg/HeliBoard/blob/v4.0/README.md#license>

The upstream `v4.0` tree has no separate root `NOTICE` or `COPYING` file. The
three license files, source-file copyright headers, and README credits are the
notices present in the selected upstream revision and must be carried forward
where applicable.
