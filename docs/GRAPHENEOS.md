# CipherBoard on GrapheneOS

This guide covers installation, keyboard enablement, permission hardening, and
stable updates without granting CipherBoard network access.

## Install and Verify

1. Download `CipherBoard-<version>-release.apk` and its `.sha256` file from the
   matching stable release at
   `https://github.com/bglglzd/CipherBoard/releases`.
2. Verify the APK SHA-256 and compare its signing-certificate SHA-256 with
   [`SIGNING_CERTIFICATE_SHA256`](../SIGNING_CERTIFICATE_SHA256) through a
   separately trusted channel where possible.
3. Install the verified APK. With ADB:

   ```sh
   adb install -r CipherBoard-<version>-release.apk
   ```

4. Open **Settings > System > Keyboard > On-screen keyboard > Manage on-screen
   keyboards** and enable CipherBoard. Menu wording can vary between GrapheneOS
   releases.
5. In **Settings > Apps > CipherBoard**, deny **Network** as defense in depth.
   Deny **Sensors** when exposed and unnecessary. Grant **Camera** only when you
   deliberately start local QR scanning. Do not grant Contacts, SMS, or storage
   access.

Keep the bootloader locked and use a strong device PIN or password. Avoid
untrusted Accessibility services because they can weaken the confidentiality
of on-screen data.

## Stable Updates with Obtainium

CipherBoard has no network capability and cannot check GitHub itself. To track
stable releases without adding `android.permission.INTERNET` to CipherBoard,
use Obtainium as an external installer:

1. Install Obtainium from a source you trust and review the permissions and
   security implications of giving it network and package-installation access.
2. In Obtainium, add this app source:

   ```text
   https://github.com/bglglzd/CipherBoard
   ```

3. Leave **Include pre-releases** disabled.
4. If an APK link filter is needed, use:

   ```regex
   ^CipherBoard-[0-9]+\.[0-9]+\.[0-9]+-release\.apk$
   ```

5. Check that the selected asset is the single production APK named
   `CipherBoard-<version>-release.apk`, then install the update over the current
   version.

Android may require confirmation for the first installation or an update. This
depends on the Android version, system policy, and whether Obtainium is the
installer that owns the existing installation. Do not weaken GrapheneOS
security settings to suppress a legitimate platform prompt.

Never uninstall CipherBoard before updating. Uninstallation deletes app data,
including the Vault, local cryptographic identity, contacts, and ratchet state;
contacts then need to pair again. Android must accept an update only when the
application ID and signing certificate match and the version code increases.
If Android reports a signature conflict, stop and investigate. Do not uninstall
the trusted installation to bypass the warning.

Obtainium is a separate trust boundary: it uses the network and retrieves the
release while CipherBoard remains offline. Automatic tracking does not replace
verification of important release notes, hashes, and signer continuity.
