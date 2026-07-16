from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import shutil
import stat
import tempfile
import unittest
import zipfile
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "release_bundle.py"
SPEC = importlib.util.spec_from_file_location("release_bundle", SCRIPT)
assert SPEC and SPEC.loader
release_bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_bundle)


class ReleaseBundleTest(unittest.TestCase):
    artifact = "CipherBoard"
    version = "1.2.3"

    def make_release(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        root.mkdir(parents=True, exist_ok=True)
        staging = root / "staging"
        assets = root / "assets"
        staging.mkdir()
        assets.mkdir()
        apk_name = release_bundle.apk_name(self.artifact, self.version)
        apk = staging / apk_name
        apk.write_bytes(b"signed production apk")
        (staging / f"{apk_name}.sha256").write_text(
            f"{hashlib.sha256(apk.read_bytes()).hexdigest()}  {apk_name}\n",
            encoding="ascii",
            newline="\n",
        )
        for name in release_bundle.evidence_names(self.artifact, self.version):
            (staging / name).write_bytes(f"evidence:{name}\n".encode("ascii"))
        bundle = assets / release_bundle.bundle_name(self.artifact, self.version)
        release_bundle.create_bundle(staging, bundle, self.artifact, self.version)
        shutil.copy2(apk, assets / apk.name)
        shutil.copy2(staging / f"{apk_name}.sha256", assets / f"{apk_name}.sha256")
        return staging, assets, bundle

    def test_bundle_is_deterministic_complete_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first_staging, first_assets, first_bundle = self.make_release(root / "first")
            _, _, second_bundle = self.make_release(root / "second")
            self.assertEqual(first_bundle.read_bytes(), second_bundle.read_bytes())

            expected_bundle_names = {
                *release_bundle.evidence_names(self.artifact, self.version),
                release_bundle.MANIFEST_NAME,
            }
            with zipfile.ZipFile(first_bundle) as archive:
                self.assertEqual(expected_bundle_names, set(archive.namelist()))
                for info in archive.infolist():
                    self.assertEqual(release_bundle.ZIP_TIMESTAMP, info.date_time)
                    self.assertEqual(3, info.create_system)
                    self.assertEqual(stat.S_IFREG | 0o644, info.external_attr >> 16)

            output = root / "extracted"
            release_bundle.extract_bundle(first_assets, output, self.artifact, self.version)
            self.assertEqual(expected_bundle_names, {path.name for path in output.iterdir()})
            manifest_names = {
                line.split("  ", 1)[1]
                for line in (first_staging / release_bundle.MANIFEST_NAME)
                .read_text(encoding="ascii")
                .splitlines()
            }
            apk_name = release_bundle.apk_name(self.artifact, self.version)
            self.assertEqual(
                {apk_name, f"{apk_name}.sha256", *release_bundle.evidence_names(self.artifact, self.version)},
                manifest_names,
            )

    def test_extract_rejects_unsafe_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, assets, bundle = self.make_release(root)
            names = list(release_bundle.evidence_names(self.artifact, self.version))
            names[names.index("LICENSE")] = "../LICENSE"
            names.append(release_bundle.MANIFEST_NAME)
            bundle.unlink()
            with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                for name in names:
                    info = zipfile.ZipInfo(name, release_bundle.ZIP_TIMESTAMP)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, b"x")

            with self.assertRaisesRegex(RuntimeError, "unsafe verification bundle path"):
                release_bundle.extract_bundle(assets, root / "output", self.artifact, self.version)
            self.assertFalse((root / "LICENSE").exists())

    def test_extract_enforces_entry_and_expanded_size_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, assets, _ = self.make_release(root)
            expected_count = len(release_bundle.evidence_names(self.artifact, self.version)) + 1
            with mock.patch.object(release_bundle, "MAX_ENTRIES", expected_count - 1):
                with self.assertRaisesRegex(RuntimeError, "entry limit exceeded"):
                    release_bundle.extract_bundle(assets, root / "too-many", self.artifact, self.version)
            with mock.patch.object(release_bundle, "MAX_TOTAL_FILE_BYTES", 1):
                with self.assertRaisesRegex(RuntimeError, "expanded-size limit exceeded"):
                    release_bundle.extract_bundle(assets, root / "too-large", self.artifact, self.version)
            with mock.patch.object(release_bundle, "MAX_ENTRY_BYTES", 1):
                with self.assertRaisesRegex(RuntimeError, "entry size limit exceeded"):
                    release_bundle.extract_bundle(assets, root / "large-entry", self.artifact, self.version)
            with mock.patch.object(release_bundle, "MAX_ARCHIVE_BYTES", 1):
                with self.assertRaisesRegex(RuntimeError, "archive-size limit exceeded"):
                    release_bundle.extract_bundle(assets, root / "large-archive", self.artifact, self.version)

    def test_extract_rejects_hash_mismatch_and_extra_public_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staging, assets, bundle = self.make_release(root)
            (staging / "SBOM.json").write_bytes(b"changed evidence")
            inventory = release_bundle.regular_file_inventory(staging)
            bundle.unlink()
            release_bundle.write_bundle(
                inventory,
                (*release_bundle.evidence_names(self.artifact, self.version), release_bundle.MANIFEST_NAME),
                bundle,
            )
            with self.assertRaisesRegex(RuntimeError, "release artifact hash mismatch: SBOM.json"):
                release_bundle.extract_bundle(assets, root / "hash-mismatch", self.artifact, self.version)
            self.assertFalse((root / "hash-mismatch").exists())

            (assets / "unexpected.txt").write_text("unexpected", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "public release asset inventory mismatch"):
                release_bundle.extract_bundle(assets, root / "extra-asset", self.artifact, self.version)


if __name__ == "__main__":
    unittest.main()
