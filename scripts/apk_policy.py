#!/usr/bin/env python3
"""Fail-closed static policy checks for a decoded CipherBoard APK manifest."""

from __future__ import annotations

import argparse
import pathlib
import sys
import xml.etree.ElementTree as ET
import zipfile

ANDROID = "{http://schemas.android.com/apk/res/android}"

FORBIDDEN_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

ALLOWED_SERVICE_PERMISSIONS = {
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_TEXT_SERVICE",
}

ALLOWED_ACTIVITY_ACTIONS = {
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.PROCESS_TEXT",
}

ALLOWED_RECEIVER_ACTIONS = {
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.USER_INITIALIZE",
    "android.intent.action.LOCALE_CHANGED",
}

FORBIDDEN_BINARY_MARKERS = {
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
    b"Landroid/webkit/WebView;": "WebView",
    b"Ldalvik/system/DexClassLoader;": "DexClassLoader",
    b"Ldalvik/system/InMemoryDexClassLoader;": "InMemoryDexClassLoader",
}


def android_attr(element: ET.Element, name: str) -> str | None:
    return element.get(ANDROID + name)


def component_name(element: ET.Element) -> str:
    return android_attr(element, "name") or "<unnamed>"


def actions(element: ET.Element) -> set[str]:
    return {
        value
        for action in element.findall("./intent-filter/action")
        if (value := android_attr(action, "name"))
    }


def check_manifest(path: pathlib.Path, mode: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    tree = ET.parse(path)
    root = tree.getroot()
    permissions = sorted(
        {
            value
            for element in root
            if element.tag.startswith("uses-permission")
            if (value := android_attr(element, "name"))
        }
    )
    violations = FORBIDDEN_PERMISSIONS.intersection(permissions)
    if violations:
        errors.append("forbidden permissions: " + ", ".join(sorted(violations)))

    application = root.find("application")
    if application is None:
        return errors + ["manifest has no application element"], permissions

    if android_attr(application, "allowBackup") != "false":
        errors.append("android:allowBackup must be explicitly false")
    if android_attr(application, "usesCleartextTraffic") != "false":
        errors.append("android:usesCleartextTraffic must be explicitly false")
    if mode == "release" and android_attr(application, "debuggable") == "true":
        errors.append("application is debuggable")
    if android_attr(application, "testOnly") == "true":
        errors.append("application is testOnly")

    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in application.findall(kind):
            exported = android_attr(component, "exported")
            has_filter = component.find("intent-filter") is not None
            name = component_name(component)
            if has_filter and exported is None:
                errors.append(f"{kind} {name} has an intent filter without explicit exported")
            if exported != "true":
                continue

            component_actions = actions(component)
            if (
                mode == "debug"
                and kind in {"activity", "activity-alias"}
                and name == "androidx.compose.ui.tooling.PreviewActivity"
            ):
                continue
            if kind == "service":
                permission = android_attr(component, "permission")
                if permission not in ALLOWED_SERVICE_PERMISSIONS:
                    errors.append(f"exported service {name} lacks an approved binding permission")
            elif kind == "receiver":
                profile_installer = (
                    name == "androidx.profileinstaller.ProfileInstallReceiver"
                    and android_attr(component, "permission") == "android.permission.DUMP"
                    and component_actions
                    and all(action.startswith("androidx.profileinstaller.action.") for action in component_actions)
                )
                if not profile_installer and (
                    not component_actions or not component_actions.issubset(ALLOWED_RECEIVER_ACTIONS)
                ):
                    errors.append(f"exported receiver {name} has unapproved actions")
            elif kind == "provider":
                errors.append(f"exported provider {name} is forbidden")
            else:
                if not component_actions or not component_actions.issubset(ALLOWED_ACTIVITY_ACTIONS):
                    errors.append(f"exported {kind} {name} has unapproved actions")

            for data in component.findall("./intent-filter/data"):
                scheme = android_attr(data, "scheme")
                if scheme in {"http", "https"}:
                    errors.append(f"exported {kind} {name} registers a network deep link")
                if scheme and scheme not in {"content"}:
                    errors.append(f"exported {kind} {name} registers unapproved scheme {scheme}")

    return errors, permissions


def check_apk_bytes(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        return [f"invalid APK ZIP: {error.__class__.__name__}"]

    with archive:
        names = archive.namelist()
        if names.count("AndroidManifest.xml") != 1:
            errors.append("APK must contain exactly one AndroidManifest.xml")
        candidates = [name for name in names if name.endswith(".dex") or name.endswith(".so")]
        for name in candidates:
            info = archive.getinfo(name)
            if info.file_size > 128 * 1024 * 1024:
                errors.append(f"oversized executable entry: {name}")
                continue
            data = archive.read(name)
            for marker, label in FORBIDDEN_BINARY_MARKERS.items():
                if marker in data:
                    errors.append(f"forbidden runtime marker {label} in {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--apk", required=True, type=pathlib.Path)
    parser.add_argument("--mode", choices=("debug", "release"), default="release")
    args = parser.parse_args()

    try:
        manifest_errors, permissions = check_manifest(args.manifest, args.mode)
    except (OSError, ET.ParseError) as error:
        print(f"APK policy failure: invalid decoded manifest ({error.__class__.__name__})", file=sys.stderr)
        return 1
    errors = manifest_errors + check_apk_bytes(args.apk)
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
