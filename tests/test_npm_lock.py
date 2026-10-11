"""Actual checked-in npm integrity graph and fail-closed installation checks."""
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "locks/jscpd/package.json"
LOCK = ROOT / "locks/jscpd/package-lock.json"
INSTALLER = ROOT / "scripts/install_jscpd.sh"
BASELINE = ROOT / "locks/engine-manifest-sha256.json"


class NpmIntegrityTest(unittest.TestCase):
    def test_reviewed_npm_lock_matches_scanned_baseline(self):
        expected = json.loads(BASELINE.read_text())["files"]["node/package-lock.json"]
        self.assertEqual(hashlib.sha256(LOCK.read_bytes()).hexdigest(), expected)

    def test_packages_have_registry_integrity_and_exact_version(self):
        package = json.loads(PKG.read_text())
        lock = json.loads(LOCK.read_text())
        self.assertEqual(package["dependencies"], {"jscpd": "5.4.1"})
        self.assertEqual(lock["lockfileVersion"], 3)
        self.assertEqual(lock["packages"]["node_modules/jscpd"]["version"], "5.4.1")
        for name, value in lock["packages"].items():
            if name == "":
                continue
            with self.subTest(name=name):
                self.assertEqual(value["version"], "5.4.1")
                self.assertTrue(value["resolved"].startswith("https://registry.npmjs.org/"))
                self.assertTrue(value["integrity"].startswith("sha512-"))
                self.assertEqual(len(base64.b64decode(value["integrity"][7:], validate=True)), 64)

    def _copy_into(self, directory):
        root = Path(directory)
        for rel in ("scripts/install_jscpd.sh", "locks/jscpd/package.json",
                    "locks/jscpd/package-lock.json", "locks/engine-manifest-sha256.json"):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / rel).read_bytes())
        return root

    @staticmethod
    def _run_installer(root):
        return subprocess.run(
            ["bash", str(root / "scripts/install_jscpd.sh"),
             str(root / "untrusted-tool-directory")],
            text=True, capture_output=True, check=False,
        )

    def test_modified_npm_lock_is_rejected_before_install(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._copy_into(d)
            lock = root / "locks/jscpd/package-lock.json"
            lock.write_text(lock.read_text().replace("5.4.1", "5.4.2", 1))
            outcome = self._run_installer(root)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("checksum differs from approved manifest", outcome.stderr)
            self.assertFalse((root / "untrusted-tool-directory").exists())

    def test_unapproved_artifact_source_refused_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._copy_into(d)
            lock = root / "locks/jscpd/package-lock.json"
            lock.write_text(lock.read_text().replace(
                "https://registry.npmjs.org/jscpd/-/", "https://example.org/jscpd/-", 1))
            baseline = root / "locks/engine-manifest-sha256.json"
            data = json.loads(baseline.read_text())
            data["files"]["node/package-lock.json"] = hashlib.sha256(lock.read_bytes()).hexdigest()
            baseline.write_text(json.dumps(data))
            outcome = self._run_installer(root)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertIn("non-registry npm artifact", outcome.stderr)
            self.assertFalse((root / "untrusted-tool-directory").exists())


if __name__ == "__main__":
    unittest.main()
