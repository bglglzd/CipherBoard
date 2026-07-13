#!/usr/bin/env python3
"""Fail-closed source scan for CipherBoard's offline and secret-handling policy."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


TEXT_SUFFIXES = {
    ".gradle", ".java", ".kts", ".kt", ".properties", ".rs", ".sh", ".toml", ".xml",
}
PRIVATE_FILE_SUFFIXES = {".jks", ".keystore", ".p12", ".pfx"}
RUNTIME_ROOTS = (
    "app/src/main/java/",
    "app/src/main/res/",
    "crypto-core/src/main/",
    "crypto-core/native/src/",
    "crypto-core/jni/src/",
    "pairing/src/main/",
    "secure-storage/src/main/",
)

RUNTIME_PATTERNS = {
    r"android\.permission\.(?:INTERNET|ACCESS_NETWORK_STATE|CHANGE_NETWORK_STATE|ACCESS_WIFI_STATE)":
        "network permission",
    r"\b(?:HttpURLConnection|URLConnection|ServerSocket|DatagramSocket)\b": "network API",
    r"\bjava\.net\.Socket\b": "network socket API",
    r"\b(?:okhttp3|retrofit2|io\.ktor\.client|com\.android\.volley)\b": "network client",
    r"\b(?:Firebase|Crashlytics|Sentry|Mixpanel|Amplitude|AppsFlyer)\b": "telemetry SDK",
    r"\bandroid\.webkit\.WebView\b": "WebView",
    r"\b(?:DexClassLoader|InMemoryDexClassLoader)\b": "dynamic code loading",
    r"\bSystem\.load\s*\(": "arbitrary-path native loading",
    r"(?i)\b(?:localhost|127\.0\.0\.1)\b": "loopback endpoint",
}

SECRET_PATTERNS = {
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----": "PEM private key",
    r"\bAKIA[0-9A-Z]{16}\b": "AWS access key",
    r"\bgh[opusr]_[A-Za-z0-9]{30,}\b": "GitHub token",
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b": "Slack token",
    r"\bAIza[0-9A-Za-z_-]{35}\b": "Google API key",
}

SECURE_SOURCE_PATTERNS = {
    r"android\.util\.Log": "platform log API in secure code",
    r"\bTimber\.": "logging API in secure code",
    r"putExtra\s*\([^\n]*(?:plain|clear)text": "plaintext Intent extra",
    r"setPrimaryClip\s*\([^\n]*(?:plain|clear)text": "plaintext clipboard write",
    r"SavedStateHandle[^\n]*(?:plain|clear)text": "plaintext saved state",
}


def repository_files(root: pathlib.Path) -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def read_text(path: pathlib.Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for path in repository_files(root):
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() in PRIVATE_FILE_SUFFIXES:
            errors.append(f"private signing/key container in repository: {relative}")
            continue
        text = read_text(path)
        if text is None:
            continue

        # Scanner fixtures contain marker literals by design; production files do not get this exemption.
        if relative not in {"scripts/apk_policy.py", "scripts/security_source_scan.py"} and not relative.startswith(
            "scripts/tests/"
        ):
            for pattern, label in SECRET_PATTERNS.items():
                if re.search(pattern, text):
                    errors.append(f"{label} in {relative}")

        if relative.startswith(RUNTIME_ROOTS):
            for pattern, label in RUNTIME_PATTERNS.items():
                if re.search(pattern, text):
                    errors.append(f"{label} in {relative}")

        if "/secure/" in relative or relative.startswith("app/src/main/java/org/cipherboard/"):
            for pattern, label in SECURE_SOURCE_PATTERNS.items():
                if re.search(pattern, text, re.IGNORECASE):
                    errors.append(f"{label} in {relative}")
    return errors


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
    try:
        errors = scan(root)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"security source scan failed: {error.__class__.__name__}", file=sys.stderr)
        return 1
    if errors:
        finding_count = len(set(errors))
        print(
            f"security source scan found {finding_count} policy violation(s)",
            file=sys.stderr,
        )
        return 1
    print("Security source scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
