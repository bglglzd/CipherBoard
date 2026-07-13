#!/usr/bin/env python3
"""Fail-closed static policy checks for a decoded CipherBoard APK manifest."""

from __future__ import annotations

import argparse
import pathlib
import posixpath
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

ANDROID = "{http://schemas.android.com/apk/res/android}"

FORBIDDEN_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

EXPECTED_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.READ_USER_DICTIONARY",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.VIBRATE",
    "android.permission.WRITE_USER_DICTIONARY",
}

EXPECTED_SECURITY_RESOURCES = {
    "fullBackupContent": "@xml/backup_rules",
    "dataExtractionRules": "@xml/data_extraction_rules",
    "networkSecurityConfig": "@xml/network_security_config",
}

AAPT_SPEC_RESOURCE = re.compile(
    r"^\s*spec resource\s+(?P<id>0x[0-9a-fA-F]{8})\s+"
    r"(?P<package>[A-Za-z0-9_.]+):(?P<name>xml/[A-Za-z0-9_.]+):\s+flags=",
    re.MULTILINE,
)

HOME_ACTIVITY = "helium314.keyboard.secure.home.CipherBoardHomeActivity"
PROCESS_TEXT_ACTIVITY = "helium314.keyboard.secure.decrypt.ProcessTextDecryptActivity"
IME_SERVICE = "helium314.keyboard.latin.LatinIME"
SPELL_SERVICE = "helium314.keyboard.latin.spellcheck.AndroidSpellCheckerService"
PROFILE_RECEIVER = "androidx.profileinstaller.ProfileInstallReceiver"

EXPECTED_EXPORTED_ACTIVITIES = {
    HOME_ACTIVITY: {
        "actions": frozenset({"android.intent.action.MAIN"}),
        "categories": frozenset({"android.intent.category.LAUNCHER"}),
        "mime_types": frozenset(),
    },
    PROCESS_TEXT_ACTIVITY: {
        "actions": frozenset({"android.intent.action.PROCESS_TEXT"}),
        "categories": frozenset({"android.intent.category.DEFAULT"}),
        "mime_types": frozenset({"text/plain"}),
    },
}

EXPECTED_EXPORTED_SERVICES = {
    IME_SERVICE: {
        "permission": "android.permission.BIND_INPUT_METHOD",
        "actions": frozenset({"android.view.InputMethod"}),
    },
    SPELL_SERVICE: {
        "permission": "android.permission.BIND_TEXT_SERVICE",
        "actions": frozenset({"android.service.textservice.SpellCheckerService"}),
    },
}

PROFILE_ACTIONS = frozenset(
    {
        "androidx.profileinstaller.action.INSTALL_PROFILE",
        "androidx.profileinstaller.action.SKIP_FILE",
        "androidx.profileinstaller.action.SAVE_PROFILE",
        "androidx.profileinstaller.action.BENCHMARK_OPERATION",
    }
)

# These APIs and SDKs are incompatible with CipherBoard's offline runtime model.
FORBIDDEN_RUNTIME_MARKERS = {
    b"com/google/firebase": "Firebase",
    b"com.google.firebase": "Firebase",
    b"com/google/android/gms": "Google Play Services",
    b"com.google.android.gms": "Google Play Services",
    b"com/google/ads": "Google Ads",
    b"com/facebook/ads": "Facebook Ads",
    b"io/sentry": "Sentry",
    b"com/crashlytics": "Crashlytics",
    b"com/appsflyer": "AppsFlyer",
    b"com/adjust/sdk": "Adjust",
    b"com/amplitude": "Amplitude",
    b"com/mixpanel": "Mixpanel",
    b"com/segment/analytics": "Segment analytics",
    b"com/bugsnag": "Bugsnag",
    b"com/datadog": "Datadog",
    b"com/newrelic": "New Relic",
    b"com/flurry": "Flurry analytics",
    b"com/kochava": "Kochava",
    b"io/branch": "Branch analytics",
    b"org/chromium/net": "Cronet",
    b"io/ktor/client": "Ktor client",
    b"com/android/volley": "Volley",
    b"com/apollographql": "Apollo GraphQL",
    b"Lokhttp3/OkHttpClient;": "OkHttp",
    b"Lretrofit2/Retrofit;": "Retrofit",
    b"Ljava/net/HttpURLConnection;": "HttpURLConnection",
    b"Ljava/net/URLConnection;": "URLConnection",
    b"Ljava/net/Socket;": "network Socket",
    b"Ljava/net/ServerSocket;": "network ServerSocket",
    b"Ljava/net/DatagramSocket;": "network DatagramSocket",
    b"Landroid/net/ConnectivityManager;": "ConnectivityManager",
    b"Landroid/webkit/WebView;": "WebView",
    b"Ldalvik/system/DexClassLoader;": "DexClassLoader",
    b"Ldalvik/system/InMemoryDexClassLoader;": "InMemoryDexClassLoader",
    b"localhost": "localhost endpoint",
    b"127.0.0.1": "loopback endpoint",
}

FORBIDDEN_RELEASE_MARKERS = {
    b"VaultFaultBoundaryActivity": "CipherBoard fault-injection fixture",
    b"cipherboard.test.extra.FAULT_BOUNDARY": "CipherBoard synthetic fault boundary",
    b"androidx/compose/ui/tooling/PreviewActivity": "Compose PreviewActivity",
    b"androidx.compose.ui.tooling.PreviewActivity": "Compose PreviewActivity",
    b"androidx/test/": "AndroidX Test",
    b"androidx.test.": "AndroidX Test",
    b"org/junit/": "JUnit",
    b"org.junit.": "JUnit",
    b"org/robolectric": "Robolectric",
    b"org.robolectric": "Robolectric",
    b"org/mockito": "Mockito",
    b"org.mockito": "Mockito",
    b"com/facebook/stetho": "Stetho",
    b"leakcanary/": "LeakCanary",
    b"com/squareup/leakcanary": "LeakCanary",
    b"com/chuckerteam/chucker": "Chucker",
}

PRIVATE_KEY_MARKERS = {
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
}

PRIVATE_KEY_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx", ".pem", ".key")
EXECUTABLE_ENTRY_LIMIT = 128 * 1024 * 1024
ARCHIVE_UNCOMPRESSED_LIMIT = 512 * 1024 * 1024
ARCHIVE_ENTRY_LIMIT = 20_000


def android_attr(element: ET.Element, name: str) -> str | None:
    return element.get(ANDROID + name)


def parse_aapt_security_resource_ids(
    path: pathlib.Path,
    expected_package: str | None = None,
) -> dict[str, str]:
    """Resolve reviewed XML resources from an unmodified `aapt dump resources` output."""
    text = path.read_text(encoding="utf-8", errors="strict")
    expected_names = {
        value.removeprefix("@"): value for value in EXPECTED_SECURITY_RESOURCES.values()
    }
    resolved: dict[str, str] = {}
    id_to_name: dict[str, str] = {}
    for match in AAPT_SPEC_RESOURCE.finditer(text):
        package_name = match.group("package")
        resource_name = match.group("name")
        if expected_package is not None and package_name != expected_package:
            continue
        resource_id = match.group("id").lower()
        table_name = f"@{resource_name}"
        previous_name = id_to_name.get(resource_id)
        if previous_name is not None and previous_name != table_name:
            raise ValueError(f"aapt resource ID {resource_id} maps to multiple XML names")
        id_to_name[resource_id] = table_name
        if resource_name not in expected_names:
            continue
        symbolic_name = expected_names[resource_name]
        previous_id = resolved.get(symbolic_name)
        if previous_id is not None and previous_id != resource_id:
            raise ValueError(f"ambiguous aapt mapping for {symbolic_name}")
        resolved[symbolic_name] = resource_id

    missing = set(EXPECTED_SECURITY_RESOURCES.values()).difference(resolved)
    if missing:
        raise ValueError(
            "reviewed resources missing from aapt table: " + ", ".join(sorted(missing))
        )
    return resolved


def security_resource_reference_matches(
    actual: str | None,
    expected: str,
    resolved_ids: dict[str, str] | None,
) -> bool:
    if actual == expected:
        return True
    if resolved_ids is None or expected not in resolved_ids:
        return False
    resource_id = resolved_ids[expected]
    return actual in {f"@ref/{resource_id}", f"@{resource_id}"}


def resolve_component_name(name: str, package_name: str) -> str:
    if name.startswith("."):
        return package_name + name
    if "." not in name:
        return f"{package_name}.{name}"
    return name


def component_name(element: ET.Element, package_name: str) -> str:
    raw_name = android_attr(element, "name")
    return resolve_component_name(raw_name, package_name) if raw_name else "<unnamed>"


def filter_values(element: ET.Element, child: str, attribute: str = "name") -> frozenset[str]:
    return frozenset(
        value
        for item in element.findall(f"./intent-filter/{child}")
        if (value := android_attr(item, attribute))
    )


def check_single_plain_intent_filter(component: ET.Element, name: str, errors: list[str]) -> None:
    intent_filters = component.findall("intent-filter")
    if len(intent_filters) != 1:
        errors.append(f"exported component {name} must have exactly one intent filter")
        return
    if intent_filters[0].attrib:
        errors.append(f"exported component {name} has unapproved intent-filter attributes")


def check_exported_activity(
    component: ET.Element,
    name: str,
    errors: list[str],
) -> None:
    expected = EXPECTED_EXPORTED_ACTIVITIES.get(name)
    if expected is None:
        errors.append(f"exported activity {name} is not allowlisted")
        return

    check_single_plain_intent_filter(component, name, errors)
    if android_attr(component, "permission") is not None:
        errors.append(f"exported activity {name} has an unexpected component permission")

    actual = {
        "actions": filter_values(component, "action"),
        "categories": filter_values(component, "category"),
        "mime_types": filter_values(component, "data", "mimeType"),
    }
    for key, expected_values in expected.items():
        if actual[key] != expected_values:
            errors.append(
                f"exported activity {name} has unexpected {key}: "
                f"{', '.join(sorted(actual[key])) or '<none>'}"
            )
    data_elements = component.findall("./intent-filter/data")
    for data in data_elements:
        allowed_attributes = {ANDROID + "mimeType"}
        unexpected = set(data.attrib).difference(allowed_attributes)
        if unexpected:
            errors.append(f"exported activity {name} has routing data beyond MIME type")


def check_exported_service(
    component: ET.Element,
    name: str,
    errors: list[str],
) -> None:
    expected = EXPECTED_EXPORTED_SERVICES.get(name)
    if expected is None:
        errors.append(f"exported service {name} is not allowlisted")
        return
    check_single_plain_intent_filter(component, name, errors)
    if android_attr(component, "permission") != expected["permission"]:
        errors.append(f"exported service {name} lacks its required binding permission")
    actual_actions = filter_values(component, "action")
    if actual_actions != expected["actions"]:
        errors.append(
            f"exported service {name} has unexpected actions: "
            f"{', '.join(sorted(actual_actions)) or '<none>'}"
        )
    if filter_values(component, "category") or component.findall("./intent-filter/data"):
        errors.append(f"exported service {name} has unapproved routing fields")


def check_exported_receiver(
    component: ET.Element,
    name: str,
    errors: list[str],
) -> None:
    if name != PROFILE_RECEIVER:
        errors.append(f"exported receiver {name} is forbidden")
        return
    if android_attr(component, "permission") != "android.permission.DUMP":
        errors.append("ProfileInstallReceiver must require android.permission.DUMP")
    intent_filters = component.findall("intent-filter")
    if len(intent_filters) != len(PROFILE_ACTIONS):
        errors.append("ProfileInstallReceiver must have one intent filter per reviewed action")
    for intent_filter in intent_filters:
        filter_actions = {
            android_attr(action, "name") for action in intent_filter.findall("action")
        }
        if intent_filter.attrib or len(filter_actions) != 1 or None in filter_actions:
            errors.append("ProfileInstallReceiver has an unapproved intent-filter structure")
    actual_actions = filter_values(component, "action")
    if actual_actions != PROFILE_ACTIONS:
        errors.append("ProfileInstallReceiver actions differ from the reviewed allowlist")
    if filter_values(component, "category") or component.findall("./intent-filter/data"):
        errors.append("ProfileInstallReceiver has unapproved routing fields")


def check_manifest(
    path: pathlib.Path,
    mode: str,
    expected_package: str | None = None,
    expected_version_name: str | None = None,
    expected_version_code: str | None = None,
    security_resource_ids: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    tree = ET.parse(path)
    root = tree.getroot()
    package_name = root.get("package") or ""
    if not package_name:
        errors.append("manifest package is missing")
    if expected_package is not None and package_name != expected_package:
        errors.append(f"manifest package mismatch: {package_name or '<missing>'}")
    version_name = android_attr(root, "versionName")
    version_code = android_attr(root, "versionCode")
    if expected_version_name is not None and version_name != expected_version_name:
        errors.append(f"manifest versionName mismatch: {version_name or '<missing>'}")
    if expected_version_code is not None and version_code != expected_version_code:
        errors.append(f"manifest versionCode mismatch: {version_code or '<missing>'}")

    permissions = sorted(
        {
            value
            for element in root
            if element.tag.split("}")[-1].startswith("uses-permission")
            if (value := android_attr(element, "name"))
        }
    )
    violations = FORBIDDEN_PERMISSIONS.intersection(permissions)
    if violations:
        errors.append("forbidden permissions: " + ", ".join(sorted(violations)))
    expected_permissions = EXPECTED_PERMISSIONS | {
        f"{package_name}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
    }
    unreviewed_permissions = set(permissions).difference(expected_permissions)
    if unreviewed_permissions:
        errors.append("unreviewed permissions: " + ", ".join(sorted(unreviewed_permissions)))

    application = root.find("application")
    if application is None:
        return errors + ["manifest has no application element"], permissions

    if android_attr(application, "allowBackup") != "false":
        errors.append("android:allowBackup must be explicitly false")
    if android_attr(application, "usesCleartextTraffic") != "false":
        errors.append("android:usesCleartextTraffic must be explicitly false")
    for attribute, expected in EXPECTED_SECURITY_RESOURCES.items():
        if not security_resource_reference_matches(
            android_attr(application, attribute), expected, security_resource_ids
        ):
            errors.append(f"android:{attribute} must reference {expected}")
    if mode == "release" and android_attr(application, "debuggable") == "true":
        errors.append("application is debuggable")
    if android_attr(application, "testOnly") == "true":
        errors.append("application is testOnly")

    exported_activities: set[str] = set()
    exported_services: set[str] = set()
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in application.findall(kind):
            exported = android_attr(component, "exported")
            has_filter = component.find("intent-filter") is not None
            name = component_name(component, package_name)
            if has_filter and exported not in {"true", "false"}:
                errors.append(f"{kind} {name} has an intent filter without explicit exported")
            if exported != "true":
                continue

            if kind == "activity":
                exported_activities.add(name)
                check_exported_activity(component, name, errors)
            elif kind == "activity-alias":
                errors.append(f"exported activity-alias {name} is forbidden")
            elif kind == "service":
                exported_services.add(name)
                check_exported_service(component, name, errors)
            elif kind == "receiver":
                check_exported_receiver(component, name, errors)
            else:
                errors.append(f"exported provider {name} is forbidden")

    missing_activities = set(EXPECTED_EXPORTED_ACTIVITIES).difference(exported_activities)
    if missing_activities:
        errors.append("required exported activities missing: " + ", ".join(sorted(missing_activities)))
    missing_services = set(EXPECTED_EXPORTED_SERVICES).difference(exported_services)
    if missing_services:
        errors.append("required exported services missing: " + ", ".join(sorted(missing_services)))

    return errors, permissions


def unsafe_archive_name(name: str) -> bool:
    normalized = posixpath.normpath(name.replace("\\", "/"))
    return name.startswith(("/", "\\")) or normalized == ".." or normalized.startswith("../")


def marker_errors(data: bytes, markers: dict[bytes, str], entry_name: str) -> list[str]:
    return [f"forbidden runtime marker {label} in {entry_name}" for marker, label in markers.items() if marker in data]


def check_apk_bytes(
    path: pathlib.Path,
    mode: str,
    expected_abis: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        return [f"invalid APK ZIP: {error.__class__.__name__}"]

    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > ARCHIVE_ENTRY_LIMIT:
            errors.append(f"APK contains too many ZIP entries: {len(infos)}")
        if len(names) != len(set(names)):
            errors.append("APK contains duplicate ZIP entry names")
        if names.count("AndroidManifest.xml") != 1:
            errors.append("APK must contain exactly one AndroidManifest.xml")
        if any(unsafe_archive_name(name) for name in names):
            errors.append("APK contains an unsafe ZIP entry path")
        total_size = sum(info.file_size for info in infos)
        if total_size > ARCHIVE_UNCOMPRESSED_LIMIT:
            errors.append(f"APK uncompressed size exceeds {ARCHIVE_UNCOMPRESSED_LIMIT} bytes")

        packaged_abis = {
            parts[1]
            for name in names
            if len(parts := name.split("/")) == 3 and parts[0] == "lib" and name.endswith(".so")
        }
        if expected_abis is not None and packaged_abis != expected_abis:
            errors.append(
                "APK ABI set mismatch: " + (", ".join(sorted(packaged_abis)) or "<none>")
            )
        for abi in expected_abis or packaged_abis:
            required_crypto = f"lib/{abi}/libcipherboard_crypto_jni.so"
            if required_crypto not in names:
                errors.append(f"required crypto native library missing: {required_crypto}")

        for info in infos:
            name = info.filename
            lower_name = name.lower()
            if lower_name.endswith(PRIVATE_KEY_SUFFIXES):
                errors.append(f"private-key-like archive entry is forbidden: {name}")
                continue
            is_executable = lower_name.endswith((".dex", ".so"))
            inspect_for_keys = is_executable or (info.file_size <= 16 * 1024 * 1024)
            if is_executable and info.file_size > EXECUTABLE_ENTRY_LIMIT:
                errors.append(f"oversized executable entry: {name}")
                continue
            if not is_executable and not inspect_for_keys:
                continue
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                errors.append(f"cannot safely read APK entry: {name}")
                continue
            if inspect_for_keys and any(marker in data for marker in PRIVATE_KEY_MARKERS):
                errors.append(f"plaintext private key material found in {name}")
            if is_executable:
                errors.extend(marker_errors(data, FORBIDDEN_RUNTIME_MARKERS, name))
                if mode == "release":
                    errors.extend(marker_errors(data, FORBIDDEN_RELEASE_MARKERS, name))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--apk", required=True, type=pathlib.Path)
    parser.add_argument("--mode", choices=("debug", "release"), default="release")
    parser.add_argument("--expected-package", required=True)
    parser.add_argument("--expected-version-name", required=True)
    parser.add_argument("--expected-version-code", required=True)
    parser.add_argument("--expected-abi", action="append", required=True)
    parser.add_argument("--aapt-resources", required=True, type=pathlib.Path)
    args = parser.parse_args()

    try:
        security_resource_ids = parse_aapt_security_resource_ids(
            args.aapt_resources,
            args.expected_package,
        )
        manifest_errors, permissions = check_manifest(
            args.manifest,
            args.mode,
            args.expected_package,
            args.expected_version_name,
            args.expected_version_code,
            security_resource_ids,
        )
    except (OSError, ET.ParseError, UnicodeError, ValueError) as error:
        print(
            f"APK policy failure: invalid manifest or aapt resource table "
            f"({error.__class__.__name__}: {error})",
            file=sys.stderr,
        )
        return 1
    errors = manifest_errors + check_apk_bytes(args.apk, args.mode, set(args.expected_abi))
    if errors:
        for error in errors:
            print(f"APK policy failure: {error}", file=sys.stderr)
        return 1

    print("Runtime permissions:")
    for permission in permissions:
        print(f"  {permission}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
