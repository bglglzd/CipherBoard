# CipherBoard Third-Party Notices

CipherBoard is an unofficial modified HeliBoard distribution. This file records
the principal notices that must accompany binaries and corresponding source.
It does not remove or replace copyright headers in individual files.

## HeliBoard, OpenBoard, and AOSP Keyboard

- HeliBoard `v4.0`, commit `bd48798b99cccc99704eebf2a9259c02dbd684d5`.
- HeliBoard is a fork of OpenBoard and is licensed under GNU GPL v3.
- Portions originate from the Android Open Source Project LatinIME/Keyboard and
  retain Android Open Source Project copyright notices under Apache-2.0.
- Other credited upstream contributors include OpenBoard, LineageOS and the
  projects named in retained source headers and README credits.
- Any inherited CC BY-SA 4.0 artwork remains subject to attribution and
  share-alike requirements. CipherBoard uses distinct product branding and is
  not an official HeliBoard release.

Complete license texts and dependency notices are distributed as `LICENSE`,
`LICENSE-Apache-2.0`, `LICENSE-BlueOak-1.0.0`,
`LICENSE-BSD-3-Clause-NOTICES`, and `LICENSE-CC-BY-SA-4.0`. They are also
readable without network access from CipherBoard's Licenses screen.

## Matrix vodozemac

CipherBoard uses `vodozemac 0.10.0`, `matrix-pickle 0.2.3`, and related code
published by Matrix.org contributors under Apache License 2.0. Copyright
notices in the upstream sources include The Matrix.org Foundation C.I.C. and
the named vodozemac contributors. The Apache 2.0 license text is included in
`LICENSE-Apache-2.0`.

The use of vodozemac does not imply that the complete CipherBoard product has
been independently audited or endorsed by Matrix.org.

## Android and JVM Libraries

The release uses AndroidX (including Core, CameraX, Biometric, Compose,
Navigation, RecyclerView, Autofill and ViewPager2), Kotlin, kotlinx libraries,
ZXing, Dagger/AutoValue transitive annotations, Reorderable,
colorpicker-compose. These components are distributed
under Apache License 2.0 except for separately identified bundled or upstream
portions. CameraX artifacts declare Apache-2.0 and BSD-3-Clause license metadata.

Exact direct versions are recorded in `LICENSES.md`; the resolved Gradle graph
must be captured in the release SBOM.

## Dalek Cryptography BSD Notices

The following locked crates are BSD-3-Clause licensed:

- `curve25519-dalek 4.1.3`:
  Copyright (c) 2016-2021 isis agora lovecruft and Henry de Valence.
- `ed25519-dalek 2.2.0`:
  Copyright (c) 2017-2019 isis agora lovecruft.
- `x25519-dalek 2.0.1`:
  Copyright (c) 2017-2021 isis agora lovecruft and
  Copyright (c) 2019-2021 DebugSteven.
- `subtle 2.6.1`:
  Copyright (c) 2016-2024 Isis Agora Lovecruft and Henry de Valence.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the source notice, conditions and
disclaimer are retained; binary redistributions must reproduce them in the
documentation and/or other materials. The names of copyright holders and
contributors may not be used to endorse derived products without permission.
These components are provided without warranty, including without implied
warranties of merchantability or fitness, and their authors are not liable for
direct, indirect, incidental, special, exemplary, or consequential damages.

## minicbor Blue Oak Model License

`minicbor 0.25.1` and `minicbor-derive 0.15.3` are offered under Blue Oak Model
License 1.0.0. That license grants permission to do anything with the software
that would otherwise infringe copyright or patent rights, subject to the
license conditions and acceptance provisions. The complete license text is
included in `LICENSE-BlueOak-1.0.0` and in the offline Licenses screen.

## Rust MIT/Apache Ecosystem

The locked JNI, Serde, RustCrypto, random-number, parsing, platform and
proc-macro support crates use MIT, Apache-2.0, or compatible dual-license
expressions. This includes `jni`, `base64`, `getrandom`, `serde`, `serde_json`,
`sha2`, `zeroize`, AEAD/AES/ChaCha/HMAC/HKDF support and their locked
transitives. Exact package names, versions, source checksums and license fields
are recorded by `crypto-core/jni/Cargo.lock` and `cargo metadata --locked`.

Where a package offers MIT OR Apache-2.0, CipherBoard redistribution relies on
a compatible offered license and preserves the upstream copyright/license
files in corresponding source. The complete Apache text is shipped in
`LICENSE-Apache-2.0`.

## Test-Only Components

JUnit 4 (EPL-1.0), Mockito (MIT), Robolectric (MIT), proptest (MIT OR
Apache-2.0), and AndroidX Test (Apache-2.0) are build/test dependencies and are
not intended to be packaged in the production APK.

## No Endorsement

Names of upstream projects and contributors are used for attribution only.
CipherBoard is not represented as an official release of HeliBoard, Matrix,
Google, AndroidX, ZXing, RustCrypto, or any other upstream project.
