#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import shutil
import stat
import sys
import zipfile


MANIFEST_NAME = "RELEASE_ARTIFACTS.sha256"
STATIC_EVIDENCE_NAMES = (
    "BUILD_INFO.txt",
    "LICENSE",
    "LICENSE-Apache-2.0",
    "LICENSE-BSD-3-Clause-NOTICES",
    "LICENSE-BlueOak-1.0.0",
    "LICENSE-CC-BY-SA-4.0",
    "LICENSE-MIT",
    "LICENSES.md",
    "SBOM.json",
    "THIRD_PARTY_NOTICES.txt",
    "VULNERABILITY_SCAN.json",
)
MAX_ARCHIVE_BYTES = 768 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024
MAX_APK_HASH_BYTES = 1024
MAX_ENTRIES = 32
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TOTAL_FILE_BYTES = 768 * 1024 * 1024
MAX_NAME_BYTES = 255
READ_CHUNK_BYTES = 1024 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)")


def checked_component(value: str, label: str) -> str:
    if not SAFE_COMPONENT.fullmatch(value) or value in {".", ".."}:
        raise RuntimeError(f"invalid {label}")
    return value


def apk_name(artifact: str, version: str) -> str:
    return f"{checked_component(artifact, 'artifact name')}-{checked_component(version, 'version')}-release.apk"


def source_name(artifact: str, version: str) -> str:
    return f"{checked_component(artifact, 'artifact name')}-{checked_component(version, 'version')}-source.tar.gz"


def bundle_name(artifact: str, version: str) -> str:
    return f"{checked_component(artifact, 'artifact name')}-{checked_component(version, 'version')}-verification.zip"


def evidence_names(artifact: str, version: str) -> tuple[str, ...]:
    return (source_name(artifact, version), *STATIC_EVIDENCE_NAMES)


def sorted_names(names: set[str] | tuple[str, ...]) -> list[str]:
    return sorted(names, key=lambda name: name.encode("ascii"))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file_inventory(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError(f"not a regular directory: {directory}")
    inventory: dict[str, pathlib.Path] = {}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"unexpected non-regular entry: {path.name}")
        inventory[path.name] = path
    return inventory


def require_inventory(actual: set[str], expected: set[str], label: str) -> None:
    if actual != expected:
        missing = sorted_names(expected - actual)
        unexpected = sorted_names(actual - expected)
        raise RuntimeError(f"{label} mismatch; missing={missing!r}, unexpected={unexpected!r}")


def require_nonempty_files(inventory: dict[str, pathlib.Path]) -> None:
    for name, path in inventory.items():
        if path.stat().st_size <= 0:
            raise RuntimeError(f"empty release file: {name}")


def require_apk_hash(inventory: dict[str, pathlib.Path], name: str) -> None:
    if inventory[name].stat().st_size > MAX_APK_BYTES:
        raise RuntimeError("release APK size limit exceeded")
    if inventory[f"{name}.sha256"].stat().st_size > MAX_APK_HASH_BYTES:
        raise RuntimeError("APK hash file size limit exceeded")
    expected = f"{sha256_file(inventory[name])}  {name}\n"
    try:
        actual = inventory[f"{name}.sha256"].read_text(encoding="ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("APK hash file is not ASCII") from error
    if actual != expected:
        raise RuntimeError("standalone APK hash file is inconsistent")


def manifest_text(inventory: dict[str, pathlib.Path], names: set[str]) -> str:
    return "".join(f"{sha256_file(inventory[name])}  {name}\n" for name in sorted_names(names))


def require_bundle_sizes(inventory: dict[str, pathlib.Path], names: tuple[str, ...]) -> None:
    total = 0
    if len(names) > MAX_ENTRIES:
        raise RuntimeError("verification bundle entry limit exceeded")
    for name in names:
        size = inventory[name].stat().st_size
        if len(name.encode("ascii")) > MAX_NAME_BYTES:
            raise RuntimeError(f"verification bundle name is too long: {name}")
        if size > MAX_ENTRY_BYTES:
            raise RuntimeError(f"verification bundle entry size limit exceeded: {name}")
        total += size
        if total > MAX_TOTAL_FILE_BYTES:
            raise RuntimeError("verification bundle expanded-size limit exceeded")


def write_bundle(inventory: dict[str, pathlib.Path], names: tuple[str, ...], output: pathlib.Path) -> None:
    require_bundle_sizes(inventory, names)
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise RuntimeError("verification bundle output directory is invalid")
    if output.exists() or output.is_symlink():
        raise RuntimeError("verification bundle output already exists")
    temporary = output.with_name(f".{output.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("temporary verification bundle already exists")
    try:
        with zipfile.ZipFile(
            temporary,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in sorted_names(names):
                info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.file_size = inventory[name].stat().st_size
                info._compresslevel = 9
                with inventory[name].open("rb") as source, archive.open(info, "w") as target:
                    shutil.copyfileobj(source, target, READ_CHUNK_BYTES)
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            raise RuntimeError("verification bundle archive-size limit exceeded")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def create_bundle(staging: pathlib.Path, output: pathlib.Path, artifact: str, version: str) -> None:
    apk = apk_name(artifact, version)
    if output.name != bundle_name(artifact, version):
        raise RuntimeError("invalid verification bundle output name")
    evidence = evidence_names(artifact, version)
    hashed_names = {apk, f"{apk}.sha256", *evidence}
    inventory = regular_file_inventory(staging)
    require_inventory(set(inventory), hashed_names, "release staging inventory")
    require_nonempty_files(inventory)
    require_apk_hash(inventory, apk)
    manifest = staging / MANIFEST_NAME
    manifest.write_text(manifest_text(inventory, hashed_names), encoding="ascii", newline="\n")
    inventory[MANIFEST_NAME] = manifest
    write_bundle(inventory, (*evidence, MANIFEST_NAME), output)


def validate_zip_entry(info: zipfile.ZipInfo) -> None:
    name = info.filename
    parsed = pathlib.PurePosixPath(name)
    if (
        not name
        or len(name.encode("utf-8")) > MAX_NAME_BYTES
        or parsed.is_absolute()
        or len(parsed.parts) != 1
        or parsed.name != name
        or name in {".", ".."}
        or "\\" in name
    ):
        raise RuntimeError(f"unsafe verification bundle path: {name!r}")
    mode = info.external_attr >> 16
    if info.is_dir() or info.create_system != 3 or mode != (stat.S_IFREG | 0o644):
        raise RuntimeError(f"unsupported verification bundle entry type: {name!r}")
    if info.flag_bits & 0x1:
        raise RuntimeError(f"encrypted verification bundle entry: {name!r}")
    if info.compress_type != zipfile.ZIP_DEFLATED:
        raise RuntimeError(f"unsupported verification bundle compression: {name!r}")
    if info.date_time != ZIP_TIMESTAMP:
        raise RuntimeError(f"non-deterministic verification bundle timestamp: {name!r}")
    if info.file_size > MAX_ENTRY_BYTES:
        raise RuntimeError(f"verification bundle entry size limit exceeded: {name}")
    if name == MANIFEST_NAME and info.file_size > MAX_MANIFEST_BYTES:
        raise RuntimeError("release artifact manifest size limit exceeded")


def extract_bundle_archive(archive_path: pathlib.Path, output: pathlib.Path, expected_names: set[str]) -> None:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise RuntimeError("verification bundle is not a regular file")
    archive_size = archive_path.stat().st_size
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        raise RuntimeError("verification bundle archive-size limit exceeded")
    if output.exists() or output.is_symlink():
        raise RuntimeError("verification bundle output must not already exist")

    with zipfile.ZipFile(archive_path, "r") as archive:
        if archive.comment:
            raise RuntimeError("verification bundle archive comment is not allowed")
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise RuntimeError("verification bundle entry limit exceeded")
        seen: set[str] = set()
        total = 0
        for info in infos:
            validate_zip_entry(info)
            if info.filename in seen:
                raise RuntimeError(f"duplicate verification bundle entry: {info.filename!r}")
            seen.add(info.filename)
            total += info.file_size
            if total > MAX_TOTAL_FILE_BYTES:
                raise RuntimeError("verification bundle expanded-size limit exceeded")
        require_inventory(seen, expected_names, "verification bundle inventory")

        output.mkdir(mode=0o700)
        try:
            actual_total = 0
            for info in infos:
                target = output / info.filename
                entry_total = 0
                with archive.open(info, "r") as source, target.open("xb") as destination:
                    while chunk := source.read(READ_CHUNK_BYTES):
                        entry_total += len(chunk)
                        actual_total += len(chunk)
                        if entry_total > MAX_ENTRY_BYTES or actual_total > MAX_TOTAL_FILE_BYTES:
                            raise RuntimeError("verification bundle extracted-size limit exceeded")
                        destination.write(chunk)
                if entry_total != info.file_size:
                    raise RuntimeError(f"verification bundle size mismatch: {info.filename}")
        except Exception:
            shutil.rmtree(output)
            raise


def parse_manifest(path: pathlib.Path, expected_names: set[str]) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("release artifact manifest is not ASCII") from error
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = MANIFEST_LINE.fullmatch(line)
        if not match:
            raise RuntimeError(f"invalid release manifest line {line_number}")
        digest, name = match.groups()
        if name == MANIFEST_NAME or name in entries:
            raise RuntimeError(f"invalid or duplicate release artifact: {name}")
        entries[name] = digest
    require_inventory(set(entries), expected_names, "release artifact manifest")
    return entries


def extract_bundle(assets: pathlib.Path, output: pathlib.Path, artifact: str, version: str) -> None:
    apk = apk_name(artifact, version)
    archive = bundle_name(artifact, version)
    evidence = evidence_names(artifact, version)
    public_names = {apk, f"{apk}.sha256", archive}
    inventory = regular_file_inventory(assets)
    require_inventory(set(inventory), public_names, "public release asset inventory")
    require_nonempty_files(inventory)
    require_apk_hash(inventory, apk)
    extract_bundle_archive(inventory[archive], output, {*evidence, MANIFEST_NAME})

    try:
        hashed_names = {apk, f"{apk}.sha256", *evidence}
        entries = parse_manifest(output / MANIFEST_NAME, hashed_names)
        for name, expected_digest in entries.items():
            path = inventory[name] if name in public_names else output / name
            if sha256_file(path) != expected_digest:
                raise RuntimeError(f"release artifact hash mismatch: {name}")
    except Exception:
        shutil.rmtree(output)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--staging-dir", type=pathlib.Path, required=True)
    create.add_argument("--output", type=pathlib.Path, required=True)
    create.add_argument("--artifact", required=True)
    create.add_argument("--version", required=True)
    extract = subparsers.add_parser("extract")
    extract.add_argument("--assets-dir", type=pathlib.Path, required=True)
    extract.add_argument("--output-dir", type=pathlib.Path, required=True)
    extract.add_argument("--artifact", required=True)
    extract.add_argument("--version", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "create":
            create_bundle(args.staging_dir, args.output, args.artifact, args.version)
        else:
            extract_bundle(args.assets_dir, args.output_dir, args.artifact, args.version)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        print(f"release bundle error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
