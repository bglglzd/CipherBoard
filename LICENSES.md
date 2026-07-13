# CipherBoard Licensing Inventory

This inventory was checked against the repository state and resolved dependency
metadata on 2026-07-13. It is not a substitute for preserving source-file
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
| desugar_jdk_libs | 2.1.5 | Apache-2.0 with upstream OpenJDK notices |
| ZXing Core | 3.5.4 | Apache-2.0 |
| Reorderable | 3.1.0 | Apache-2.0 |
| colorpicker-compose | 1.1.3 | Apache-2.0 |

AndroidX transitives, Dagger, AutoValue annotations, Kotlin coroutines,
JetBrains Compose compatibility artifacts, JSpecify and the empty Guava
`listenablefuture` conflict artifact are resolved transitively. Their POM
license metadata is predominantly Apache-2.0; applicable BSD notices from
CameraX are retained in packaged Android dependency metadata.

**Reproducibility limitation:** Gradle dependency locking is not enabled and
there is no checked-in Gradle lockfile. Direct versions and the Compose BOM are
fixed, but the exact transitive graph is not yet cryptographically locked.
Release engineering must enable and review Gradle locks before calling the
build reproducible.

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

The remaining locked runtime crates are the RustCrypto cipher/MAC/KDF stack,
`rand`, `digest`, `signature`, `curve25519-dalek` support crates, Serde support,
JNI support, proc-macro output and platform support. Cargo metadata reports
MIT, Apache-2.0, compatible dual-license expressions, BSD, or BlueOak terms.
No locked Cargo package lacks a license field. Exact names and checksums are in
the lockfiles; notices requiring reproduction are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Build and Test Dependencies

These are not intended to be packaged in the release APK:

| Component | Version | License |
| --- | --- | --- |
| Gradle | 8.14 | Apache-2.0 |
| cargo-ndk | 4.1.2 used by the verified environment | MIT OR Apache-2.0 |
| proptest | 1.6.0 | MIT OR Apache-2.0 |
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
SBOM and automated license-report artifact are still required for a production
release; this hand-maintained inventory must be rechecked whenever a lockfile,
BOM, or direct dependency changes.
