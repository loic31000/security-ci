"""Tests of pre-install Python hashes and Go module checksum enforcement."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "locks/python-tools.txt"


def parse_lock(path):
    results = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.!+_-]+) --hash=sha256:([0-9a-f]{64})",
            line,
        )
        if not match:
            raise ValueError(f"unpinned or unhashed distribution in {path}: {line[:80]}")
        key = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if key in results:
            raise ValueError(f"duplicate locked package: {key}")
        results[key] = (match.group(2), match.group(3))
    return results


class InstallLockTests(unittest.TestCase):
    def test_python_lock_is_complete_and_explicitly_hashed(self):
        packages = parse_lock(FULL)
        self.assertGreaterEqual(len(packages), 70)
        for root in ("semgrep", "zizmor", "radon", "lizard", "defusedxml", "pytest"):
            self.assertIn(root, packages)
        for name in ("python-report-tests.txt", "python-maintainability.txt", "python-zizmor.txt"):
            subset = parse_lock(ROOT / "locks" / name)
            self.assertTrue(subset)
            self.assertTrue(set(subset).issubset(set(packages)))
            for key, value in subset.items():
                self.assertEqual(value, packages[key])

    def test_go_lock_matches_reviewed_baseline(self):
        expected = json.loads((ROOT / "locks/engine-manifest-sha256.json").read_text())["files"]
        for filename in ("go.mod", "go.sum"):
            locked = ROOT / "locks/gitleaks" / filename
            self.assertGreater(locked.stat().st_size, 1000)
            self.assertEqual(hashlib.sha256(locked.read_bytes()).hexdigest(), expected["go/" + filename])
        go_mod = (ROOT / "locks/gitleaks/go.mod").read_text()
        for pinned in ("github.com/zricethezav/gitleaks/v8 v8.30.1",
                       "golang.org/x/crypto v0.55.0", "golang.org/x/text v0.41.0"):
            self.assertIn(pinned, go_mod)

    def test_builder_rejects_tampered_go_sum_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "locks/gitleaks").mkdir(parents=True)
            for rel in ("scripts/build_gitleaks.sh", "locks/gitleaks/go.mod",
                        "locks/gitleaks/go.sum", "locks/engine-manifest-sha256.json"):
                (root / rel).write_bytes((ROOT / rel).read_bytes())
            summation = root / "locks/gitleaks/go.sum"
            summation.write_bytes(summation.read_bytes() + b"# deliberate tampering\n")
            result = subprocess.run(
                ["bash", str(root / "scripts/build_gitleaks.sh"),
                 str(root / "temporary-module"), str(root / "binary")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum differs from reviewed baseline", result.stderr)
            self.assertFalse((root / "binary/gitleaks").exists())

    def test_pip_rejects_bad_wheel_hash_before_install(self):
        # A fabricated, harmless local wheel. No PyPI traffic or actual install.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "audit_canary-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as z:
                z.writestr("audit_canary/__init__.py", "__version__ = '1.0'\n")
                z.writestr("audit_canary-1.0.dist-info/METADATA",
                           "Metadata-Version: 2.1\nName: audit-canary\nVersion: 1.0\n")
                z.writestr("audit_canary-1.0.dist-info/WHEEL",
                           "Wheel-Version: 1.0\nGenerator: security-ci\n"
                           "Root-Is-Purelib: true\nTag: py3-none-any\n")
                z.writestr("audit_canary-1.0.dist-info/RECORD", "")
            real_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            for digest, allowed in ((real_digest, True), ("0" * 64, False)):
                with self.subTest(correct_hash=allowed):
                    req = root / "single.txt"
                    req.write_text("audit-canary==1.0 --hash=sha256:" + digest + "\n")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "download", "--no-index",
                         "--no-deps", "--require-hashes", "--no-cache-dir",
                         "--find-links", str(root), "--dest", str(root / ("ok" if allowed else "bad")),
                         "-r", str(req)],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)


if __name__ == "__main__":
    unittest.main()
