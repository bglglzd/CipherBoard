#!/usr/bin/env python3
"""Generate release SBOM and BUILD_INFO from resolved inputs and a verified APK."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import uuid
import xml.etree.ElementTree as ET


def run(command: list[str], cwd: pathlib.Path) -> str:
    process = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode != 0:
        raise RuntimeError(f"metadata command failed: {command[0]}")
    return process.stdout


def require_match(pattern: str, text: str, label: str, flags: int = 0) -> str:
    match = re.search(pattern, text, flags)
    if not match:
        raise RuntimeError(f"cannot determine {label}")
    return match.group(1)


def normalize_license(name: str) -> str:
    lowered = name.lower()
    if "apache" in lowered and "2" in lowered:
        return "Apache-2.0"
    if "mit" in lowered:
        return "MIT"
    if "bsd" in lowered and "3" in lowered:
        return "BSD-3-Clause"
    if "eclipse public" in lowered or "epl" in lowered:
        return "EPL-1.0"
    return name.strip()


def pom_license(group: str, artifact: str, version: str) -> str | None:
    base = (
        pathlib.Path.home()
        / ".gradle"
        / "caches"
        / "modules-2"
        / "files-2.1"
        / group
        / artifact
        / version
    )
    expressions: list[str] = []
    for pom in base.glob("**/*.pom"):
        try:
            root = ET.parse(pom).getroot()
        except (OSError, ET.ParseError):
            continue
        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}", 1)[0] + "}"
        for element in root.findall(f"./{namespace}licenses/{namespace}license/{namespace}name"):
            if element.text:
                expressions.append(normalize_license(element.text))
    if not expressions:
        return None
    return " OR ".join(sorted(set(expressions)))


def known_gradle_license(group: str, artifact: str) -> str | None:
    if group.startswith("androidx.") or group.startswith("org.jetbrains."):
        return "Apache-2.0"
    if group.startswith("org.jetbrainsx.") or group.startswith("org.jetbrains.kotlinx"):
        return "Apache-2.0"
    if group.startswith("com.google.dagger") or group.startswith("com.google.auto.value"):
        return "Apache-2.0"
    if group in {
        "com.google.zxing",
        "com.google.guava",
        "com.android.tools",
        "com.android.tools.build",
        "sh.calvin.reorderable",
        "com.github.skydoves",
        "org.jspecify",
        "jakarta.inject",
        "javax.inject",
    }:
        return "Apache-2.0"
    if artifact == "kotlin-stdlib":
        return "Apache-2.0"
    return None


def gradle_components(root: pathlib.Path) -> list[dict[str, object]]:
    gradlew = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    output = run(
        [
            str(gradlew),
            ":app:dependencies",
            "--configuration",
            "releaseRuntimeClasspath",
            "--console=plain",
            "--no-configuration-cache",
        ],
        root,
    )
    coordinates: set[tuple[str, str, str]] = set()
    pattern = re.compile(
        r"--- ([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\s()]+)(?: -> ([^\s()]+))?"
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        group, artifact, declared, resolved = match.groups()
        version = resolved or declared
        if version.startswith("{") or version in {"unspecified", "FAILED"}:
            continue
        coordinates.add((group, artifact, version))

    components: list[dict[str, object]] = []
    for group, artifact, version in sorted(coordinates):
        license_expression = pom_license(group, artifact, version) or known_gradle_license(group, artifact)
        component: dict[str, object] = {
            "type": "library",
            "group": group,
            "name": artifact,
            "version": version,
            "bom-ref": f"pkg:maven/{urllib.parse.quote(group)}/{urllib.parse.quote(artifact)}@{urllib.parse.quote(version)}",
            "purl": f"pkg:maven/{urllib.parse.quote(group)}/{urllib.parse.quote(artifact)}@{urllib.parse.quote(version)}",
        }
        if license_expression:
            component["licenses"] = [{"expression": license_expression}]
        else:
            component["properties"] = [{"name": "cipherboard:licenseReview", "value": "required"}]
        components.append(component)
    if not components:
        raise RuntimeError("resolved Gradle runtime graph was empty")
    return components


def cargo_components(root: pathlib.Path) -> list[dict[str, object]]:
    metadata = json.loads(
        run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--filter-platform",
                "aarch64-linux-android",
                "--format-version",
                "1",
                "--manifest-path",
                "crypto-core/jni/Cargo.toml",
            ],
            root,
        )
    )
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root_id = metadata["resolve"]["root"]
    pending = [root_id]
    included: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in included:
            continue
        included.add(package_id)
        for dependency in nodes[package_id].get("deps", []):
            if any(kind.get("kind") in {None, "build"} for kind in dependency.get("dep_kinds", [])):
                pending.append(dependency["pkg"])

    components: list[dict[str, object]] = []
    for package_id in sorted(included, key=lambda item: (packages[item]["name"], packages[item]["version"])):
        package = packages[package_id]
        name = package["name"]
        version = package["version"]
        component: dict[str, object] = {
            "type": "library",
            "name": name,
            "version": version,
            "bom-ref": f"pkg:cargo/{urllib.parse.quote(name)}@{urllib.parse.quote(version)}",
            "purl": f"pkg:cargo/{urllib.parse.quote(name)}@{urllib.parse.quote(version)}",
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        components.append(component)
    return components


def generate_sbom(root: pathlib.Path, output: pathlib.Path, timestamp: str, version: str) -> None:
    components = gradle_components(root) + cargo_components(root)
    seen: set[str] = set()
    unique = []
    for component in components:
        reference = str(component["bom-ref"])
        if reference not in seen:
            seen.add(reference)
            unique.append(component)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "CipherBoard release_metadata.py"}]},
            "component": {
                "type": "application",
                "name": "CipherBoard",
                "version": version,
                "purl": f"pkg:apk/org.cipherboard.securekeyboard@{urllib.parse.quote(version)}",
            },
        },
        "components": unique,
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_build_info(
    root: pathlib.Path,
    apk: pathlib.Path,
    output: pathlib.Path,
    apksigner: str,
    apkanalyzer: str,
    timestamp: str,
) -> None:
    gradle_properties = (root / "gradle.properties").read_text(encoding="utf-8")
    app_gradle = (root / "app/build.gradle.kts").read_text(encoding="utf-8")
    root_gradle = (root / "build.gradle.kts").read_text(encoding="utf-8")
    wrapper = (root / "gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
    upstream = (root / "UPSTREAM.md").read_text(encoding="utf-8")
    cargo_toml = (root / "crypto-core/native/Cargo.toml").read_text(encoding="utf-8")

    version = require_match(r"^cipherboard\.versionName=(.+)$", gradle_properties, "version", re.M)
    cert_output = run([apksigner, "verify", "--verbose", "--print-certs", str(apk)], root)
    certificate = require_match(
        r"(?:Signer #1|V[0-9]+ Signer): certificate SHA-256 digest: ([0-9a-fA-F]+)",
        cert_output,
        "certificate fingerprint",
    )
    permissions_output = run([apkanalyzer, "manifest", "permissions", str(apk)], root)
    permissions = sorted(
        line.strip() for line in permissions_output.splitlines() if line.strip().startswith("android.permission.")
    )
    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    java_version = run(["java", "-version"], root).splitlines()[0]

    values = [
        ("Git commit", run(["git", "rev-parse", "HEAD"], root).strip()),
        ("HeliBoard upstream tag", require_match(r"^- Tag: `([^`]+)`", upstream, "upstream tag", re.M)),
        ("HeliBoard upstream commit", require_match(r"^- Commit: `([0-9a-f]{40})`", upstream, "upstream commit", re.M)),
        ("Android Gradle Plugin", require_match(r'com\.android\.tools\.build:gradle:([^\"]+)', root_gradle, "AGP")),
        ("Gradle", require_match(r"gradle-([0-9.]+)-bin\.zip", wrapper, "Gradle")),
        ("Java", java_version),
        ("Android compileSdk", require_match(r"compileSdk\s*=\s*([0-9]+)", app_gradle, "compileSdk")),
        ("Android targetSdk", require_match(r"targetSdk\s*=\s*([0-9]+)", app_gradle, "targetSdk")),
        ("Android minSdk", require_match(r"minSdk\s*=\s*([0-9]+)", app_gradle, "minSdk")),
        ("Android NDK", require_match(r"ndkVersion\s*=\s*\"([^\"]+)\"", app_gradle, "NDK")),
        ("Rust", run(["rustc", "--version"], root).strip()),
        ("vodozemac", require_match(r"vodozemac\s*=\s*\{\s*version\s*=\s*\"=([^\"]+)\"", cargo_toml, "vodozemac")),
        ("Build date UTC", timestamp),
        ("Supported ABIs", "arm64-v8a, x86_64"),
        ("APK SHA-256", apk_hash),
        ("Signing certificate SHA-256", certificate.lower()),
        ("APK", apk.name),
        ("Version", version),
        ("Runtime permissions", ", ".join(permissions) if permissions else "none"),
    ]
    output.write_text("\n".join(f"{key}: {value}" for key, value in values) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--apk", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--apksigner", required=True)
    parser.add_argument("--apkanalyzer", required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    apk = args.apk.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    properties = (root / "gradle.properties").read_text(encoding="utf-8")
    version = require_match(r"^cipherboard\.versionName=(.+)$", properties, "version", re.M)
    generate_sbom(root, output / "SBOM.json", timestamp, version)
    generate_build_info(root, apk, output / "BUILD_INFO.txt", args.apksigner, args.apkanalyzer, timestamp)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"release metadata failure: {error}", file=sys.stderr)
        raise SystemExit(1)
