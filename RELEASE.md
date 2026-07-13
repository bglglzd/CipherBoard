# CipherBoard Release Procedure

This procedure is fail-closed. A release is not approved merely because an APK
was produced. Every blocker in `SECURITY_REVIEW.md` and
`SECURITY_CHECKLIST.md` must be resolved and the final APK must pass
`scripts/verify-apk`.

## Signing Material

Keep release signing material outside the repository. The default locations
are:

```text
~/.local/share/cipherboard/signing/cipherboard-release.jks
~/.config/cipherboard/signing.properties
```

Create a new keystore only once, interactively, outside the repository. Abort
if the target file already exists. Do not put passwords on a command line. The
initial key parameters are EC P-256 with SHA-256/ECDSA and a long-lived local
certificate:

```text
keytool -genkeypair -v -keystore ~/.local/share/cipherboard/signing/cipherboard-release.jks -storetype PKCS12 -alias cipherboard-release -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -validity 10000 -dname "CN=CipherBoard Release, OU=Release Signing, O=CipherBoard"
```

Omit `-storepass` and `-keypass` and answer the password prompts. Generate a
unique high-entropy password with an offline password manager or operating-
system CSPRNG, and never print it into build logs. The build scripts never run
`keytool`, never overwrite a keystore, and never print passwords.

The properties file format is deliberately restricted to one literal
`key=value` per line:

```properties
storeFile=/absolute/path/to/cipherboard-release.jks
storePassword=REDACTED
keyAlias=cipherboard-release
keyPassword=REDACTED
```

Java-properties escaping and multiline values are not supported by the release
scripts. Use strong randomly generated values without line breaks. On POSIX:

```sh
chmod 700 ~/.local/share/cipherboard/signing ~/.config/cipherboard
chmod 600 ~/.local/share/cipherboard/signing/cipherboard-release.jks
chmod 600 ~/.config/cipherboard/signing.properties
```

PowerShell release builds inspect the ACL and allow only the current user,
SYSTEM, and local Administrators. Store passwords still transit through JVM and
PowerShell string memory; absolute RAM zeroization cannot be guaranteed. They
are passed to `apksigner` through restricted temporary files, never command
arguments.

Back up the keystore and its passwords separately in secure offline locations.
Losing the signing key prevents safe updates to existing installations. A
leaked key allows malicious updates and requires an incident response; it is
not recoverable by changing the application password.

`SIGNING_CERTIFICATE_SHA256` is a public, non-secret pin for the reviewed
release certificate. Keep it under source review. The release verifier rejects
a validly signed APK whose signer differs from this pin; changing it is a key-
continuity event and must never be bundled into an unrelated release.

## Pre-release Checklist

1. Start from a clean, reviewed commit and record its full hash.
2. Update `cipherboard.versionCode` monotonically and set the intended semantic
   `cipherboard.versionName`.
3. Confirm the pinned HeliBoard and crypto revisions in `UPSTREAM.md` and the
   Cargo lockfiles. Confirm `app/gradle.lockfile` matches the reviewed
   packageable dependency graphs. For an intentional dependency update only,
   regenerate it with:

   ```sh
   ./gradlew :app:resolveApplicationDependencyLocks --write-locks --no-configuration-cache
   ```

4. Resolve every release blocker in `SECURITY_REVIEW.md`.
5. Regenerate and review the CycloneDX SBOM and dependency/license report
   produced by the release scripts. Resolve every component marked
   `cipherboard:licenseReview=required`.
6. Run full app/library unit tasks, all module release lint tasks, Rust
   formatting/clippy/test/audit, the pinned cargo-fuzz smoke campaign, and the
   Android instrumentation/crash-atomicity suite on a clean checkout. Archive
   the exact commands and results. The current API 36 AOSP run passes 7/7 in its
   documented process-text/viewer/clipboard/vault/SIGKILL scope; the final run
   must not describe untested SQLite-statement, real `commitText()` acknowledgement
   or full IME/composer/camera paths as covered. The release script must repeat
   the pinned offline OSV gate and its exact-run report must be reviewed. The
   pre-public local signed candidate passed for all 255 packages with zero
   findings; that unpublished result does not substitute for rerunning the
   final public release tag.
7. Record physical GrapheneOS, camera, StrongBox and TEE-fallback validation as
   residual assurance required before high-risk use. Missing physical evidence
   limits assurance but is not itself a demonstrated critical code defect.
8. Review the final merged manifest and every exported component.
9. Confirm no secret, plaintext fixture, keystore, signing properties, generated
   `.so`, or debug database is staged in Git.

## Build and Sign

Unix-like shell:

```sh
CIPHERBOARD_SIGNING_PROPERTIES="$HOME/.config/cipherboard/signing.properties" \
  CIPHERBOARD_OSV_SCANNER="/absolute/path/to/osv-scanner" \
  scripts/build-release.sh
```

PowerShell 7:

```powershell
$env:CIPHERBOARD_SIGNING_PROPERTIES = "$HOME/.config/cipherboard/signing.properties"
$env:CIPHERBOARD_OSV_SCANNER = "$HOME/.local/share/cipherboard/tools/osv-scanner/2.4.0/osv-scanner.exe"
./scripts/build-release.ps1
```

The scripts build an unsigned/aligned intermediate in temporary storage and
write only the signed result and release metadata to `dist/`. They do not
create signing material. A pre-existing destination APK may be replaced, but
the keystore is opened read-only by `apksigner` and is never replaced.

Expected outputs produced by the current release script are:

```text
dist/CipherBoard-<version>-release.apk
dist/CipherBoard-<version>-release.apk.sha256
dist/CipherBoard-<version>-source.tar.gz
dist/SBOM.json
dist/VULNERABILITY_SCAN.json
dist/RELEASE_ARTIFACTS.sha256
dist/BUILD_INFO.txt
dist/THIRD_PARTY_NOTICES.txt
dist/LICENSE
dist/LICENSE-Apache-2.0
dist/LICENSE-BSD-3-Clause-NOTICES
dist/LICENSE-BlueOak-1.0.0
dist/LICENSE-CC-BY-SA-4.0
dist/LICENSE-MIT
dist/LICENSES.md
```

`SBOM.json` is CycloneDX 1.5 and is generated from the resolved Gradle release
runtime graph plus the locked Android Cargo graph. The release fails if the
graph is empty or any component lacks reviewed license metadata.
`BUILD_INFO.txt` is generated only
after signing and verification and records the required toolchain, upstream,
APK hash, certificate and runtime-permission evidence.

Artifact-specific claims must cite the `BUILD_INFO.txt`, APK hash file, and
`RELEASE_ARTIFACTS.sha256` produced by the same clean run. Results from an older
candidate must never be carried forward to a changed commit or tag.

The vulnerability report is produced only after an official OSV-Scanner v2.4.0
binary matches a pinned release SHA-256, both local Maven and crates.io databases
are present and no more than seven days old, every SBOM package is scanned
offline, and the result contains zero findings. `RELEASE_ARTIFACTS.sha256`
hashes every staged output and is verified again after publication.

The source archive is created with `git archive` from the exact clean commit
that produced the APK. The APK also packages GPLv3, Apache-2.0, BlueOak-1.0.0,
BSD-3-Clause notices, CC BY-SA, upstream provenance and the dependency inventory
as offline assets for the non-exported local license viewer. A unit test checks
that every required asset is present and nonempty. These generated outputs still
require manual completeness review; their existence alone is not license approval.

## Independent Verification

Run verification again in a separate clean environment:

```sh
scripts/verify-apk.sh dist/CipherBoard-<version>-release.apk
sha256sum dist/CipherBoard-<version>-release.apk
(cd dist && sha256sum --check RELEASE_ARTIFACTS.sha256)
```

Record:

- APK SHA-256;
- signing certificate SHA-256 and subject;
- full runtime permission list;
- Git commit, upstream commit, toolchain versions and supported ABIs;
- test and `VULNERABILITY_SCAN.json` results;
- every hash in `RELEASE_ARTIFACTS.sha256`.

Compare the certificate fingerprint to a separately stored trusted record. Do
not derive trust solely from a fingerprint published next to the APK on the
same potentially compromised channel.

## Distribution and Installation

Publish the signed APK, SHA-256, signing certificate fingerprint, generated
source archive, GPL/Apache/BlueOak/CC license texts, BSD notices, SBOM,
vulnerability report, artifact hash manifest and build information through the
intended trusted channel. Users should verify the hash and certificate, keep the
bootloader locked, use a strong device credential, and disable the GrapheneOS
Network permission for CipherBoard as defense in depth.

Updates must be signed by the same release key and use a greater version code.
Test upgrade behavior without restoring or rolling back ratchet state.

## High-risk Use

Do not describe this release as independently audited unless such an audit has
actually occurred. Before high-risk use, obtain external review of the Android
IME boundary, JNI codec, pairing transcript, state-commit protocol, Keystore
integration, secure viewer, and final reproducible build.

Only after the exact release artifact has passed the recorded automated suite
may the final report include this required, narrowly scoped statement:

> Сборка реализует проверенные криптографические примитивы и прошла
> автоматические тесты, но весь продукт не следует считать независимо
> аудированным до проверки внешним специалистом по прикладной криптографии и
> Android security.

At the 2026-07-13 verification snapshot, full app/library unit and module lint
gates, 27 native Rust tests, and a 601,574-input ASan/libFuzzer envelope campaign
pass. A clean pre-public local signed-candidate pipeline also verified the pinned
official OSV-Scanner v2.4.0, fresh offline Maven/crates.io databases, all 255
SBOM packages, release signing, the merged APK policy, and artifact hashes. Its
local evidence bundle is neither tracked nor published and is not evidence for
the rewritten public history. The final public tag must repeat the complete run
and publish its own `BUILD_INFO.txt` and release assets.

Targeted API 36 x86_64 AOSP no-Play instrumentation passes 7/7 with zero
failures/skips, including two vault reopen tests and three actual debug-only
remote-process SIGKILL boundaries. It does not cover failure inside individual
SQLite statements, the ambiguous real `InputConnection.commitText()`
acknowledgement window, full IME/composer/live-camera E2E, or physical platform
validation. No physical GrapheneOS acceptance or independent audit is claimed,
and those remain prerequisites before high-risk use.
