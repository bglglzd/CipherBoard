from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "osv_offline_scan.py"
SPEC = importlib.util.spec_from_file_location("osv_offline_scan", SCRIPT)
assert SPEC and SPEC.loader
osv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(osv)


class OsvOfflineScanTest(unittest.TestCase):
    def test_sbom_requires_complete_cyclonedx_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sbom = pathlib.Path(directory) / "SBOM.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "components": [{"purl": "pkg:maven/example/item@1", "version": "1"}],
                    }
                ),
                encoding="utf-8",
            )
            count, digest = osv.validate_sbom(sbom)
            self.assertEqual(1, count)
            self.assertEqual(osv.sha256(sbom), digest)

            sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                osv.validate_sbom(sbom)

    def test_database_gate_rejects_stale_files(self) -> None:
        now = dt.datetime(2026, 7, 13, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for ecosystem, filename in osv.DATABASES:
                path = root / ecosystem / filename
                path.parent.mkdir(parents=True)
                path.write_bytes(b"database")
                timestamp = (now - dt.timedelta(days=8)).timestamp()
                os.utime(path, (timestamp, timestamp))
            with self.assertRaises(RuntimeError):
                osv.validate_databases(root, now)


if __name__ == "__main__":
    unittest.main()
