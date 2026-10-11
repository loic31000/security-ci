"""Dependency reproducibility and CycloneDX report-validation regression tests."""
import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "manifest_provenance.py"
spec = importlib.util.spec_from_file_location("manifest_provenance", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManifestEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.baseline = {"schema_version": 1, "files": {}}
        for name in module.EXPECTED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            contents = ("test dependency: " + name + "\n").encode()
            path.write_bytes(contents)
            self.baseline["files"][name] = hashlib.sha256(contents).hexdigest()

    def test_complete_and_unchanged_manifests_pass(self):
        hashes = module.verify_manifests(self.root, self.baseline)
        self.assertEqual(set(hashes), set(module.EXPECTED))

    def test_manifest_mutation_or_deletion_is_technical_failure(self):
        p = self.root / "go" / "go.sum"
        p.write_text("different version")
        with self.assertRaisesRegex(module.EvidenceError, "dependency drift"):
            module.verify_manifests(self.root, self.baseline)
        p.unlink()
        with self.assertRaisesRegex(module.EvidenceError, "missing"):
            module.verify_manifests(self.root, self.baseline)

    def test_bad_baseline_or_missing_family_refused(self):
        invalid = dict(self.baseline)
        invalid["files"] = {k: v for k, v in self.baseline["files"].items() if k != "node/package-lock.json"}
        with self.assertRaisesRegex(module.EvidenceError, "missing a required"):
            module.verify_manifests(self.root, invalid)
        invalid["files"] = dict(self.baseline["files"], **{"go/go.sum": "fake"})
        with self.assertRaisesRegex(module.EvidenceError, "bad SHA"):
            module.verify_manifests(self.root, invalid)

    def test_cyclonedx_real_trivy_shape_with_unversioned_roots(self):
        data = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "application", "name": name}
                for name in module.EXPECTED if name != "go/go.sum"
            ] + [
                {"type": "library", "name": "semgrep", "version": "1.179.0"},
                {"type": "library", "name": "jscpd", "version": "5.4.1"},
                {"type": "library", "name": "example.com/security-ci-gitleaks-build"},
            ],
        }
        self.assertEqual(module.verify_cyclonedx(data), 6)

    def test_cyclonedx_missing_root_is_not_full_coverage(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "components": [{"type": "application", "name": "go/go.mod"},
                               {"type": "application", "name": "python/requirements.txt"},
                               {"type": "library", "name": "semgrep", "version": "1.179.0"}]}
        with self.assertRaisesRegex(module.EvidenceError, "missing one or more"):
            module.verify_cyclonedx(data)

    def test_empty_or_invalid_sbom_never_passes(self):
        examples = (
            {},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
            {"bomFormat": "not-cyclonedx", "specVersion": "1.6",
             "components": [{"name": "x", "version": "1"}]},
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [{"name": "x"}]},
            {"bomFormat": "CycloneDX", "specVersion": "9.9",
             "components": [{"name": "x", "version": "1"}]},
        )
        for data in examples:
            with self.subTest(data=data), self.assertRaises(module.EvidenceError):
                module.verify_cyclonedx(data)

    def test_symlinked_manifest_is_refused(self):
        link = self.root / "python" / "requirements.txt"
        original = self.root / "requirements-original.txt"
        original.write_bytes(link.read_bytes())
        link.unlink()
        link.symlink_to(original)
        with self.assertRaisesRegex(module.EvidenceError, "symlinked"):
            module.verify_manifests(self.root, self.baseline)


if __name__ == "__main__":
    unittest.main()
