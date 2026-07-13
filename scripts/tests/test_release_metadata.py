from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "release_metadata.py"
SPEC = importlib.util.spec_from_file_location("release_metadata", SCRIPT)
assert SPEC and SPEC.loader
release_metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_metadata)


class ReleaseMetadataTest(unittest.TestCase):
    def test_property_must_be_unique_and_nonempty(self) -> None:
        self.assertEqual("value", release_metadata.require_property("key=value\n", "key"))
        with self.assertRaises(RuntimeError):
            release_metadata.require_property("key=a\nkey=b\n", "key")
        with self.assertRaises(RuntimeError):
            release_metadata.require_property("key=\n", "key")

    def test_abis_are_derived_from_verified_apk_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = pathlib.Path(directory) / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/x86_64/libexample.so", b"x")
                archive.writestr("lib/arm64-v8a/libexample.so", b"x")
                archive.writestr("assets/lib/not-an-abi.so", b"x")
            self.assertEqual(["arm64-v8a", "x86_64"], release_metadata.apk_abis(apk))

    def test_signing_fingerprint_accepts_current_and_legacy_apksigner_formats(self) -> None:
        digest = "ab" * 32
        for line in (
            f"Signer #1 certificate SHA-256 digest: {digest}",
            f"Signer #1: certificate SHA-256 digest: {digest}",
            f"V3 Signer: certificate SHA-256 digest: {digest}",
        ):
            with self.subTest(line=line):
                self.assertEqual(digest, release_metadata.signing_certificate_sha256(line))

        colon_digest = ":".join("ab" for _ in range(32))
        self.assertEqual(
            digest,
            release_metadata.signing_certificate_sha256(
                f"Signer #1 certificate SHA-256 digest: {colon_digest}"
            ),
        )

    def test_sbom_uses_central_identity_and_signed_apk_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "SBOM.json"
            apk = pathlib.Path(directory) / "signed.apk"
            apk.write_bytes(b"signed-apk")
            component = {
                "type": "library",
                "name": "item",
                "version": "1",
                "bom-ref": "pkg:maven/example/item@1",
                "purl": "pkg:maven/example/item@1",
                "licenses": [{"expression": "Apache-2.0"}],
            }
            with mock.patch.object(release_metadata, "gradle_components", return_value=[component]), mock.patch.object(
                release_metadata, "cargo_components", return_value=[]
            ):
                release_metadata.generate_sbom(
                    pathlib.Path(directory),
                    output,
                    "2026-07-13T00:00:00Z",
                    "1.2.3",
                    "example.changed.package",
                    "Changed Product",
                    apk,
                )
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                "pkg:apk/example.changed.package@1.2.3",
                document["metadata"]["component"]["purl"],
            )
            self.assertEqual("Changed Product", document["metadata"]["component"]["name"])
            self.assertEqual(
                release_metadata.hashlib.sha256(b"signed-apk").hexdigest(),
                document["metadata"]["component"]["hashes"][0]["content"],
            )
            self.assertEqual(
                document["metadata"]["component"]["bom-ref"],
                document["dependencies"][0]["ref"],
            )

    def test_sbom_rejects_dependency_without_reviewed_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "SBOM.json"
            apk = pathlib.Path(directory) / "signed.apk"
            apk.write_bytes(b"signed-apk")
            component = {
                "type": "library",
                "name": "unknown",
                "version": "1",
                "bom-ref": "pkg:maven/example/unknown@1",
                "purl": "pkg:maven/example/unknown@1",
            }
            with mock.patch.object(release_metadata, "gradle_components", return_value=[component]), mock.patch.object(
                release_metadata, "cargo_components", return_value=[]
            ):
                with self.assertRaises(RuntimeError):
                    release_metadata.generate_sbom(
                        pathlib.Path(directory),
                        output,
                        "2026-07-13T00:00:00Z",
                        "1.2.3",
                        "example.changed.package",
                        "Changed Product",
                        apk,
                    )


if __name__ == "__main__":
    unittest.main()
