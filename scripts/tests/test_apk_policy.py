from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
import zipfile


SCRIPT = pathlib.Path(__file__).parents[1] / "apk_policy.py"
SPEC = importlib.util.spec_from_file_location("apk_policy", SCRIPT)
assert SPEC and SPEC.loader
apk_policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(apk_policy)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def valid_manifest(extra_component: str = "", application_attributes: str = "") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="org.cipherboard.securekeyboard">
  <uses-permission android:name="android.permission.CAMERA" />
  <application android:allowBackup="false" android:usesCleartextTraffic="false"
      android:fullBackupContent="@xml/backup_rules"
      android:dataExtractionRules="@xml/data_extraction_rules"
      android:networkSecurityConfig="@xml/network_security_config" {application_attributes}>
    <activity android:name="helium314.keyboard.secure.home.CipherBoardHomeActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:name="helium314.keyboard.secure.decrypt.ProcessTextDecryptActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.PROCESS_TEXT" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="text/plain" />
      </intent-filter>
    </activity>
    <service android:name="helium314.keyboard.latin.LatinIME"
        android:permission="android.permission.BIND_INPUT_METHOD" android:exported="true">
      <intent-filter><action android:name="android.view.InputMethod" /></intent-filter>
    </service>
    <service android:name="helium314.keyboard.latin.spellcheck.AndroidSpellCheckerService"
        android:permission="android.permission.BIND_TEXT_SERVICE" android:exported="true">
      <intent-filter><action android:name="android.service.textservice.SpellCheckerService" /></intent-filter>
    </service>
    <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver"
        android:permission="android.permission.DUMP" android:exported="true">
      <intent-filter><action android:name="androidx.profileinstaller.action.INSTALL_PROFILE" /></intent-filter>
      <intent-filter><action android:name="androidx.profileinstaller.action.SKIP_FILE" /></intent-filter>
      <intent-filter><action android:name="androidx.profileinstaller.action.SAVE_PROFILE" /></intent-filter>
      <intent-filter><action android:name="androidx.profileinstaller.action.BENCHMARK_OPERATION" /></intent-filter>
    </receiver>
    {extra_component}
  </application>
</manifest>
"""


class ManifestPolicyTest(unittest.TestCase):
    def check(self, xml: str, mode: str = "release") -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.xml"
            path.write_text(xml, encoding="utf-8")
            errors, _ = apk_policy.check_manifest(path, mode)
            return errors

    def test_reviewed_manifest_passes(self) -> None:
        self.assertEqual([], self.check(valid_manifest()))

    def test_unexpected_exported_activity_is_rejected(self) -> None:
        component = '<activity android:name=".Unreviewed" android:exported="true" />'
        self.assertTrue(any("not allowlisted" in error for error in self.check(valid_manifest(component))))

    def test_reviewed_activity_cannot_gain_an_extra_filter(self) -> None:
        xml = valid_manifest().replace(
            "</activity>",
            "<intent-filter><action android:name=\"android.intent.action.MAIN\" /></intent-filter></activity>",
            1,
        )
        self.assertTrue(any("exactly one intent filter" in error for error in self.check(xml)))

    def test_spell_checker_settings_activity_is_not_an_exception(self) -> None:
        component = """
          <activity android:name="helium314.keyboard.latin.spellcheck.SpellCheckerSettingsActivity"
              android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
          </activity>
        """
        self.assertTrue(any("not allowlisted" in error for error in self.check(valid_manifest(component))))

    def test_unexpected_exported_receiver_is_rejected(self) -> None:
        component = '<receiver android:name=".Receiver" android:exported="true" />'
        self.assertTrue(any("exported receiver" in error for error in self.check(valid_manifest(component))))

    def test_profile_receiver_requires_dump_permission(self) -> None:
        xml = valid_manifest().replace('android:permission="android.permission.DUMP"', "")
        self.assertTrue(any("must require" in error for error in self.check(xml)))

    def test_exported_service_requires_exact_binding_permission(self) -> None:
        xml = valid_manifest().replace(
            'android:permission="android.permission.BIND_INPUT_METHOD"',
            'android:permission="android.permission.BIND_TEXT_SERVICE"',
        )
        self.assertTrue(any("binding permission" in error for error in self.check(xml)))

    def test_required_component_cannot_silently_disappear(self) -> None:
        xml = valid_manifest().replace(
            'android:name="helium314.keyboard.secure.home.CipherBoardHomeActivity" android:exported="true"',
            'android:name="helium314.keyboard.secure.home.CipherBoardHomeActivity" android:exported="false"',
        )
        self.assertTrue(any("required exported activities missing" in error for error in self.check(xml)))

    def test_release_rejects_debuggable_and_all_modes_reject_test_only(self) -> None:
        self.assertIn("application is debuggable", self.check(valid_manifest(application_attributes='android:debuggable="true"')))
        self.assertNotIn(
            "application is debuggable",
            self.check(valid_manifest(application_attributes='android:debuggable="true"'), "debug"),
        )
        self.assertIn("application is testOnly", self.check(valid_manifest(application_attributes='android:testOnly="true"'), "debug"))

    def test_unreviewed_permission_is_rejected(self) -> None:
        xml = valid_manifest().replace(
            "<uses-permission android:name=\"android.permission.CAMERA\" />",
            "<uses-permission android:name=\"android.permission.BLUETOOTH_CONNECT\" />",
        )
        self.assertTrue(any("unreviewed permissions" in error for error in self.check(xml)))

    def test_identity_and_security_resource_mismatches_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.xml"
            path.write_text(valid_manifest(), encoding="utf-8")
            errors, _ = apk_policy.check_manifest(
                path,
                "release",
                "org.example.wrong",
                "0.1.0",
                "10000",
            )
        self.assertTrue(any("package mismatch" in error for error in errors))
        xml = valid_manifest().replace("@xml/backup_rules", "@xml/wrong")
        self.assertTrue(any("fullBackupContent" in error for error in self.check(xml)))


class ArchivePolicyTest(unittest.TestCase):
    def make_apk(self, entries: dict[str, bytes]) -> pathlib.Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = pathlib.Path(directory.name) / "test.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"binary manifest placeholder")
            for name, value in entries.items():
                archive.writestr(name, value)
        return path

    def test_release_rejects_test_sdk_but_debug_does_not(self) -> None:
        apk = self.make_apk({"classes.dex": b"prefix androidx/test/runner suffix"})
        self.assertTrue(any("AndroidX Test" in error for error in apk_policy.check_apk_bytes(apk, "release")))
        self.assertEqual([], apk_policy.check_apk_bytes(apk, "debug"))

    def test_release_rejects_cipherboard_fault_fixture_but_debug_does_not(self) -> None:
        apk = self.make_apk({"classes.dex": b"prefix VaultFaultBoundaryActivity suffix"})
        self.assertTrue(any(
            "fault-injection fixture" in error
            for error in apk_policy.check_apk_bytes(apk, "release")
        ))
        self.assertEqual([], apk_policy.check_apk_bytes(apk, "debug"))

    def test_network_client_marker_is_rejected_in_debug_too(self) -> None:
        apk = self.make_apk({"classes.dex": b"prefix Lokhttp3/OkHttpClient; suffix"})
        self.assertTrue(any("OkHttp" in error for error in apk_policy.check_apk_bytes(apk, "debug")))

    def test_private_key_filename_and_material_are_rejected(self) -> None:
        named = self.make_apk({"assets/release.keystore": b"opaque"})
        inline = self.make_apk({"assets/config.txt": b"-----BEGIN PRIVATE KEY-----"})
        self.assertTrue(any("private-key-like" in error for error in apk_policy.check_apk_bytes(named, "release")))
        self.assertTrue(any("private key material" in error for error in apk_policy.check_apk_bytes(inline, "release")))

    def test_path_traversal_is_rejected(self) -> None:
        apk = self.make_apk({"../payload": b"x"})
        self.assertTrue(any("unsafe ZIP entry" in error for error in apk_policy.check_apk_bytes(apk, "release")))

    def test_release_requires_exact_abi_and_crypto_library(self) -> None:
        valid = self.make_apk({"lib/arm64-v8a/libcipherboard_crypto_jni.so": b"ELF"})
        wrong = self.make_apk({"lib/x86_64/libcipherboard_crypto_jni.so": b"ELF"})
        missing = self.make_apk({"lib/arm64-v8a/libother.so": b"ELF"})
        self.assertEqual([], apk_policy.check_apk_bytes(valid, "release", {"arm64-v8a"}))
        self.assertTrue(any("ABI set mismatch" in error for error in apk_policy.check_apk_bytes(
            wrong, "release", {"arm64-v8a"}
        )))
        self.assertTrue(any("crypto native library missing" in error for error in apk_policy.check_apk_bytes(
            missing, "release", {"arm64-v8a"}
        )))


if __name__ == "__main__":
    unittest.main()
