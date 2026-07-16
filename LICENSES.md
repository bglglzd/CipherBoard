# CipherBoard Licensing Inventory

This inventory was checked against the repository state and resolved dependency
metadata on 2026-07-14. It is not a substitute for preserving source-file
headers or the complete license texts shipped in this repository.

## CipherBoard and HeliBoard

CipherBoard is an unofficial modified version of HeliBoard and is distributed
under GNU GPL version 3 only. The complete GPLv3 text is [`LICENSE`](LICENSE).
The pinned upstream is HeliBoard `v4.0`, commit
`bd48798b99cccc99704eebf2a9259c02dbd684d5`; see [`UPSTREAM.md`](UPSTREAM.md).

Inherited AOSP Keyboard code is Apache-2.0. The complete Apache 2.0 text is
[`LICENSE-Apache-2.0`](LICENSE-Apache-2.0). Inherited artwork that remains from
the upstream CC BY-SA set is covered by
[`LICENSE-CC-BY-SA-4.0`](LICENSE-CC-BY-SA-4.0). CipherBoard branding does not
claim affiliation with HeliBoard.

The complete Blue Oak Model License used by `minicbor` is retained in
[`LICENSE-BlueOak-1.0.0`](LICENSE-BlueOak-1.0.0). Consolidated BSD-3-Clause
notices for the applicable resolved components are retained in
[`LICENSE-BSD-3-Clause-NOTICES`](LICENSE-BSD-3-Clause-NOTICES). Exact MIT
copyright and permission notices for the MIT-only resolved components are
retained in [`LICENSE-MIT`](LICENSE-MIT).

## Word Presentation Dictionaries

The English and Russian 4096-word presentation dictionaries are generated
derivative datasets from
[`hermitdave/FrequencyWords`](https://github.com/hermitdave/FrequencyWords),
commit `525f9b560de45753a5ea01069454e72e9aa541c6`. The exact upstream inputs are:

- `content/2018/en/en_50k.txt`
- `content/2018/ru/ru_50k.txt`

FrequencyWords identifies its content as Creative Commons Attribution-
ShareAlike 4.0 (`CC-BY-SA-4.0`). CipherBoard redistributes the generated lists
under the same content license; the complete text is
[`LICENSE-CC-BY-SA-4.0`](LICENSE-CC-BY-SA-4.0).

The generation process extracts the word column, keeps only already-lowercase
alphabetic English ASCII or Russian Cyrillic words of 4--10 letters,
deduplicates entries, removes profanity and alarming words/fragments, then
takes a deterministic 4096-entry list in source-frequency order. These
transformations produce codebook tokens, not natural phrases or a language
model. The exact generated UTF-8 files are pinned by SHA-256:

| Generated file | SHA-256 |
| --- | --- |
| `crypto-core/native/data/words_en_v1.txt` | `620b96da9c31f8552a6ed8eb54ef22a9a9a6b7885d2caf4ba9f658b748cf0cb3` |
| `crypto-core/native/data/words_ru_v1.txt` | `6163eddf094c8c426959c1bb36d95dca3d7cbe4bdecc13bd13077279b7ccc8a9` |

The dictionary bytes are versioned protocol data. Reordering, replacing, or
silently regenerating them would break `CBW1` interoperability and requires a
new presentation version plus license review.

## Android Runtime Dependencies

The versions below are direct declarations in the current Gradle build. The
resolved Android runtime graph can be inspected with:

```sh
./gradlew :app:dependencies --configuration releaseRuntimeClasspath
```

| Component | Pinned declaration | License |
| --- | --- | --- |
| Android Gradle Plugin / ViewBinding | 8.13.2 | Apache-2.0 |
| Kotlin stdlib and compiler plugins | 2.3.20 | Apache-2.0 |
| AndroidX Core KTX | 1.17.0 | Apache-2.0 |
| AndroidX RecyclerView | 1.4.0 | Apache-2.0 |
| AndroidX Autofill | 1.3.0 | Apache-2.0 |
| AndroidX ViewPager2 | 1.1.0 | Apache-2.0 |
| AndroidX Biometric | 1.1.0 | Apache-2.0 |
| CameraX camera2/lifecycle/view | 1.6.1 | Apache-2.0; bundled BSD portions |
| AndroidX Compose BOM | 2025.11.01 | Apache-2.0 |
| AndroidX Navigation Compose | 2.9.8 | Apache-2.0 |
| kotlinx.serialization JSON | 1.11.0 | Apache-2.0 |
| ZXing Core | 3.5.4 | Apache-2.0 |
| Reorderable | 3.1.0 | Apache-2.0 |
| colorpicker-compose | 1.1.3 | Apache-2.0 |

AndroidX transitives, Dagger, AutoValue annotations, Kotlin coroutines,
JetBrains Compose compatibility artifacts, JSpecify and the empty Guava
`listenablefuture` conflict artifact are resolved transitively. Their POM
license metadata is predominantly Apache-2.0; applicable BSD notices from
CameraX are retained in packaged Android dependency metadata.

Packageable application configurations use strict Gradle dependency locking.
The reviewed resolved graph is committed in `app/gradle.lockfile`; intentional
dependency changes must regenerate that file and review its diff together with
the SBOM. This locks resolved versions, but does not by itself prove artifact
provenance, license compatibility, or absence of vulnerabilities.

## Rust Runtime Dependencies

Direct Rust dependencies are exact-version requirements and the complete
graphs are fixed by `crypto-core/native/Cargo.lock` and
`crypto-core/jni/Cargo.lock`.

| Crate | Version | License metadata |
| --- | --- | --- |
| vodozemac | 0.10.0 | Apache-2.0 |
| matrix-pickle / derive | 0.2.3 | Apache-2.0 |
| prost / derive | 0.14.4 | Apache-2.0 |
| minicbor / derive | 0.25.1 / 0.15.3 | BlueOak-1.0.0 |
| bytes | 1.12.1 | MIT |
| combine | 4.6.7 | MIT |
| generic-array | 0.14.7 | MIT |
| jni | 0.21.1 | MIT OR Apache-2.0 |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| getrandom | 0.2.16 | MIT OR Apache-2.0 |
| serde / derive | 1.0.219 | MIT OR Apache-2.0 |
| serde_json | 1.0.140 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| zeroize / derive | 1.8.2 / 1.5.0 | Apache-2.0 OR MIT |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| x25519-dalek | 2.0.1 | BSD-3-Clause |
| subtle | 2.6.1 | BSD-3-Clause |

`cargo tree --target aarch64-linux-android --edges normal` and the target
artifacts show that `bytes`, `combine`, and `generic-array` are the MIT-only
crates linked into the Android JNI artifact. The remaining locked runtime
crates are the RustCrypto cipher/MAC/KDF stack, `rand`, `digest`, `signature`,
`curve25519-dalek` support crates, Serde support, JNI support, proc-macro
output and platform support. Cargo metadata reports MIT, Apache-2.0,
compatible dual-license expressions, BSD, or BlueOak terms. No locked Cargo
package lacks a license field. Exact names and checksums are in the lockfiles;
notices requiring reproduction are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Build and Test Dependencies

These are not intended to be packaged in the release APK:

| Component | Version | License |
| --- | --- | --- |
| Gradle | 8.14 | Apache-2.0 |
| cargo-ndk | 4.1.2 used by the verified environment | MIT OR Apache-2.0 |
| cargo-fuzz | 0.13.2 | MIT OR Apache-2.0 |
| libfuzzer-sys | 0.4.13 | MIT OR Apache-2.0 |
| proptest | 1.6.0 | MIT OR Apache-2.0 |
| winnow (host proc-macro graph) | 0.7.15 / 1.0.3 | MIT |
| JUnit 4 | 4.13.2 | EPL-1.0 |
| Mockito | 5.23.0 | MIT |
| Robolectric | 4.16.1 | MIT |
| AndroidX Test runner/core/ext | 1.7.0 / 1.7.0 / 1.3.0 | Apache-2.0 |

## Verification Evidence

Rust license metadata was extracted with:

```sh
cargo metadata --locked --format-version 1 \
  --manifest-path crypto-core/jni/Cargo.toml
cargo tree --locked --target aarch64-linux-android --edges normal \
  --manifest-path crypto-core/jni/Cargo.toml
```

Gradle POM metadata was checked from the resolved release graph. A generated
CycloneDX SBOM path now exists in the release scripts, but its exact-release
output and every `cipherboard:licenseReview=required` component still require
manual review. The release preflight used a SHA-pinned official OSV-Scanner
v2.4.0 binary and fresh local Maven/crates.io databases to scan all 255 SBOM
packages offline; it exited successfully with zero findings. The clean final
release must repeat and archive this result. This inventory must be rechecked
whenever a lockfile, BOM, or direct dependency changes.

## Offline Distribution

The APK build copies `LICENSE`, `LICENSE-Apache-2.0`, `LICENSE-MIT`,
`LICENSE-BlueOak-1.0.0`, `LICENSE-BSD-3-Clause-NOTICES`,
`LICENSE-CC-BY-SA-4.0`, this inventory, `THIRD_PARTY_NOTICES.md`, and
`UPSTREAM.md` into generated `licenses/` assets. A non-exported local activity
renders those packaged files without a network lookup, and a unit test requires
every listed asset to exist and be nonempty. Release staging also creates
`CipherBoard-<version>-source.tar.gz` from the exact clean Git commit and
publishes the standalone license documents plus `THIRD_PARTY_NOTICES.txt`
beside the APK. The final archive, assets, notices, and resolved SBOM must still
be inspected together before distribution.
