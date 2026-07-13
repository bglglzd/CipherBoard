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

Create a new keystore only once, interactively, outside the repository. Do not
put passwords on a command line. For example, run `keytool -genkeypair` without
`-storepass` or `-keypass` and answer its password prompts. The build scripts
never run `keytool`, never overwrite a keystore, and never print passwords.

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

## Pre-release Checklist

1. Start from a clean, reviewed commit and record its full hash.
2. Update `cipherboard.versionCode` monotonically and set the intended semantic
   `cipherboard.versionName`.
3. Confirm the pinned HeliBoard and crypto revisions in `UPSTREAM.md` and the
   Cargo lockfiles.
4. Resolve every release blocker in `SECURITY_REVIEW.md`.
5. Regenerate and review the SBOM and dependency/license report. A complete
   automated SBOM is not yet implemented by the current scripts.
6. Run unit, instrumentation, lint, Rust formatting/clippy/test/audit, and the
   crash-atomicity suite on a clean checkout.
7. Test on current GrapheneOS without Sandboxed Google Play, on a physical
   StrongBox device and a TEE-fallback device.
8. Review the final merged manifest and every exported component.
9. Confirm no secret, plaintext fixture, keystore, signing properties, generated
   `.so`, or debug database is staged in Git.

## Build and Sign

Unix-like shell:

```sh
CIPHERBOARD_SIGNING_PROPERTIES="$HOME/.config/cipherboard/signing.properties" \
  scripts/build-release.sh
```

PowerShell 7:

```powershell
$env:CIPHERBOARD_SIGNING_PROPERTIES = "$HOME/.config/cipherboard/signing.properties"
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
dist/SBOM.json
dist/BUILD_INFO.txt
dist/THIRD_PARTY_NOTICES.txt
```

`SBOM.json` is CycloneDX 1.5 and is generated from the resolved Gradle release
runtime graph plus the locked Android Cargo graph. Components whose POM lacks
usable license metadata are marked `cipherboard:licenseReview=required` and
must be resolved during release review. `BUILD_INFO.txt` is generated only
after signing and verification and records the required toolchain, upstream,
APK hash, certificate and runtime-permission evidence.

## Independent Verification

Run verification again in a separate clean environment:

```sh
scripts/verify-apk.sh dist/CipherBoard-<version>-release.apk
sha256sum dist/CipherBoard-<version>-release.apk
```

Record:

- APK SHA-256;
- signing certificate SHA-256 and subject;
- full runtime permission list;
- Git commit, upstream commit, toolchain versions and supported ABIs;
- test and vulnerability-scan results.

Compare the certificate fingerprint to a separately stored trusted record. Do
not derive trust solely from a fingerprint published next to the APK on the
same potentially compromised channel.

## Distribution and Installation

Publish the signed APK, SHA-256, signing certificate fingerprint, corresponding
source, GPL/Apache/CC license texts, notices, SBOM and build information through
the intended trusted channel. Users should verify the hash and certificate,
keep the bootloader locked, use a strong device credential, and disable the
GrapheneOS Network permission for CipherBoard as defense in depth.

Updates must be signed by the same release key and use a greater version code.
Test upgrade behavior without restoring or rolling back ratchet state.

## High-risk Use

Do not describe this release as independently audited unless such an audit has
actually occurred. Before high-risk use, obtain external review of the Android
IME boundary, JNI codec, pairing transcript, state-commit protocol, Keystore
integration, secure viewer, and final reproducible build.

Сборка реализует проверенные криптографические примитивы и прошла автоматические
тесты, но весь продукт не следует считать независимо аудированным до проверки
внешним специалистом по прикладной криптографии и Android security.
