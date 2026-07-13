#!/usr/bin/env python3
"""Verify a pinned OSV-Scanner and scan the release SBOM without network access."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


OSV_VERSION = "2.4.0"
MAX_DATABASE_AGE = dt.timedelta(days=7)
OFFICIAL_BINARY_HASHES = {
    "088119325156321c34c456ac3703d6013538fd71cbac82b891ab34db491e4d66": "darwin_amd64",
    "9ca3185ad63e9ab54f7cb90f46a7362be02d80e37f0123d095a54355ea202f5d": "darwin_arm64",
    "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0": "linux_amd64",
    "44e580752910f0ff36ec99aff59af20f65df1e859aa31e5605a8f0d055b496e9": "linux_arm64",
    "0cdd113610126d5dfd5e12ad0e0b4f3e879291ff19bb43b0c52ed2f2c2df1a37": "windows_amd64",
    "1ce89d7d8ef083634648ef0f193fe1254f36f46f4bdc93d61178adacc2e60da0": "windows_arm64",
}
DATABASES = (("Maven", "all.zip"), ("crates.io", "all.zip"))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_scanner(scanner: pathlib.Path) -> tuple[str, str]:
    scanner_hash = sha256(scanner)
    platform = OFFICIAL_BINARY_HASHES.get(scanner_hash)
    if not platform:
        raise RuntimeError("OSV-Scanner binary does not match an approved official v2.4.0 release hash")
    process = subprocess.run(
        [str(scanner), "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode != 0 or f"osv-scanner version: {OSV_VERSION}" not in process.stdout:
        raise RuntimeError(f"OSV-Scanner must report version {OSV_VERSION}")
    return scanner_hash, platform


def validate_databases(database_root: pathlib.Path, now: dt.datetime) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    for ecosystem, filename in DATABASES:
        path = database_root / ecosystem / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"offline OSV database is missing for {ecosystem}")
        modified = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
        if now - modified > MAX_DATABASE_AGE or modified > now + dt.timedelta(minutes=5):
            raise RuntimeError(f"offline OSV database is stale or has an invalid timestamp for {ecosystem}")
        evidence.append(
            {
                "ecosystem": ecosystem,
                "sha256": sha256(path),
                "size": path.stat().st_size,
                "updatedUtc": modified.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            }
        )
    return evidence


def validate_sbom(sbom: pathlib.Path) -> tuple[int, str]:
    document = json.loads(sbom.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise RuntimeError("release SBOM is not CycloneDX 1.5")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise RuntimeError("release SBOM contains no dependency components")
    for component in components:
        if not isinstance(component, dict) or not component.get("purl") or not component.get("version"):
            raise RuntimeError("release SBOM contains an incomplete dependency component")
    return len(components), sha256(sbom)


def scan(scanner: pathlib.Path, sbom: pathlib.Path) -> tuple[dict[str, object], str]:
    with tempfile.TemporaryDirectory(prefix="cipherboard-osv-") as directory:
        scanner_input = pathlib.Path(directory) / "CipherBoard.cdx.json"
        shutil.copyfile(sbom, scanner_input)
        process = subprocess.run(
            [
                str(scanner),
                "scan",
                "source",
                "--offline",
                "--offline-vulnerabilities",
                "--format",
                "json",
                "-L",
                str(scanner_input),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("OSV-Scanner did not return valid JSON") from error
    if process.returncode != 0:
        raise RuntimeError("OSV-Scanner reported a vulnerability or scan failure")
    if result.get("results") != []:
        raise RuntimeError("OSV-Scanner returned unexpected findings with a successful exit code")
    if "Loaded Maven local db" not in process.stderr or "Loaded crates.io local db" not in process.stderr:
        raise RuntimeError("OSV-Scanner did not confirm both required local vulnerability databases")
    match = re.search(r"found (\d+) packages", process.stderr)
    if not match:
        raise RuntimeError("OSV-Scanner did not report the scanned package count")
    return result, match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", required=True, type=pathlib.Path)
    parser.add_argument("--database-root", required=True, type=pathlib.Path)
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    scanner = args.scanner.resolve(strict=True)
    database_root = args.database_root.resolve(strict=True)
    sbom = args.sbom.resolve(strict=True)
    scanner_hash, platform = validate_scanner(scanner)
    databases = validate_databases(database_root, now)
    component_count, sbom_hash = validate_sbom(sbom)
    osv_result, scanned_count_text = scan(scanner, sbom)
    scanned_count = int(scanned_count_text)
    if scanned_count != component_count:
        raise RuntimeError("OSV-Scanner package count does not match the release SBOM")

    report = {
        "schemaVersion": 1,
        "result": "pass",
        "networkMode": "offline",
        "scanner": {
            "name": "OSV-Scanner",
            "version": OSV_VERSION,
            "platformAsset": platform,
            "sha256": scanner_hash,
        },
        "databases": databases,
        "sbomSha256": sbom_hash,
        "packagesScanned": component_count,
        "knownVulnerabilities": 0,
        "scan": osv_result,
        "completedUtc": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Offline OSV scan passed for {component_count} release packages")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"offline OSV scan failure: {error}", file=sys.stderr)
        raise SystemExit(1)
