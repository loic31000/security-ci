"""Adversarial target coverage: absent != scanned != unsupported."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stack_coverage", ROOT / "scripts/stack_coverage.py")
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


def trivy(*rows):
    return {"SchemaVersion": 2, "Results": list(rows)}


def row(path, kind="gomod", cls="lang-pkgs"):
    return {"Target": path, "Type": kind, "Class": cls, "Vulnerabilities": []}


class StackCoverageTest(unittest.TestCase):
    def run_on(self, manifest_paths, rows):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for path in manifest_paths:
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("synthetic")
            return coverage.summarize(root, trivy(*rows))

    def test_recognized_go_python_pnpm_gradle_maven_cargo(self):
        manifests = ["go.mod", "requirements.txt", "web/pnpm-lock.yaml",
                     "java/gradle.lockfile", "maven/pom.xml", "Cargo.lock"]
        types = ["gomod", "pip", "pnpm", "gradle", "pom", "cargo"]
        evidence = self.run_on(manifests, [row(p, typ) for p, typ in zip(manifests, types)])
        self.assertEqual(evidence["status"], "PASS")
        for fam in ("go-modules", "python-pip", "node-pnpm", "java-gradle",
                    "java-maven", "rust-cargo"):
            self.assertEqual(evidence["families"][fam]["state"], "SCANNED")

    def test_empty_project_has_no_false_positive_coverage(self):
        summary = self.run_on([], [])
        self.assertEqual(summary["status"], "PASS")
        self.assertTrue(all(v["state"] == "NOT_APPLICABLE"
                            for v in summary["families"].values()))

    def test_two_manifests_one_scanned_is_incomplete(self):
        evidence = self.run_on(["one/go.mod", "two/go.mod"], [row("one/go.mod")])
        self.assertEqual(evidence["status"], "INCOMPLETE")
        self.assertEqual(evidence["families"]["go-modules"]["declared_manifests"], 2)
        self.assertEqual(evidence["families"]["go-modules"]["recognized_manifests"], 1)

    def test_wrong_path_or_analyzer_does_not_prove_coverage(self):
        for target in (row("backup/go.mod"), row("go.mod", "npm"),
                       row("go.mod", "gomod", "config"), row("go.mod.backup")):
            with self.subTest(target=target):
                result = self.run_on(["go.mod"], [target])
                self.assertEqual(result["status"], "INCOMPLETE")

    def test_unresolved_gradle_and_rust_are_manifest_only(self):
        result = self.run_on(["app/build.gradle", "lib/Cargo.toml", "web/package.json"], [])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["families"]["java-gradle"]["state"], "MANIFEST_ONLY")
        self.assertEqual(result["families"]["rust-cargo"]["state"], "MANIFEST_ONLY")
        self.assertEqual(result["families"]["node-npm"]["state"], "MANIFEST_ONLY")

    def test_nuget_without_proven_analyzer_is_unverified(self):
        result = self.run_on(["src/a.csproj", "packages.lock.json"], [])
        self.assertEqual(result["families"]["dotnet-nuget"]["state"], "UNVERIFIED")
        self.assertEqual(result["families"]["dotnet-nuget"]["recognized_manifests"], 0)

    def test_generated_and_vendor_sources_do_not_cause_spurious_gaps(self):
        result = self.run_on(["node_modules/package-lock.json", "vendor/go.mod",
                              "dist/Cargo.lock", ".audit-metadata/go.mod"], [])
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(all(x["state"] == "NOT_APPLICABLE" for x in result["families"].values()))

    def test_trivy_inventory_must_be_well_formed_and_safe(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ([{"Target": "go.mod"}],
                        [row("../go.mod")], [row("/etc/go.mod")],
                        [row("x//go.mod")], [row("https://example.org/go.mod")]):
                with self.subTest(rows=bad):
                    with self.assertRaises(coverage.CoverageError):
                        coverage.summarize(d, trivy(*bad))
            for invalid in ({"Results": []}, {"SchemaVersion": 2, "Results": None},
                            {"SchemaVersion": 2, "Results": [{}]}):
                with self.assertRaises(coverage.CoverageError):
                    coverage.summarize(d, invalid)

    def test_symlinked_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            outside = root / "ordinary.txt"
            outside.write_text("contents")
            (root / "go.mod").symlink_to(outside)
            with self.assertRaisesRegex(coverage.CoverageError, "symlinked"):
                coverage.summarize(root, trivy())

    def test_result_excludes_manifest_paths_and_scanner_findings(self):
        report = self.run_on(["private-project/go.mod"], [row("private-project/go.mod")])
        self.assertNotIn("private-project", json.dumps(report))
        self.assertEqual(report["families"]["go-modules"]["recognized_manifests"], 1)


if __name__ == "__main__":
    unittest.main()
