"""Adversarial checks for evidence-based Java/Gradle dependency coverage."""
import importlib.util
import json
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "java_gradle_probe", root / "scripts" / "java_gradle_probe.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def record(target="gradle.lockfile", vulnerabilities=None, analyzer="gradle"):
    return {"SchemaVersion": 2, "Results": [
        {"Target": target, "Class": "lang-pkgs", "Type": analyzer,
         "Vulnerabilities": vulnerabilities or []},
    ]}


def candidate(version="2.14.1", severity="CRITICAL", package="org.apache.logging.log4j:log4j-core"):
    return {"PkgName": package, "InstalledVersion": version,
            "Severity": severity, "VulnerabilityID": "CVE-2021-44228"}


class JavaGradleProbeTest(unittest.TestCase):
    def test_actual_positive_and_benign_target_are_distinguished(self):
        evidence = subject.probe(record(vulnerabilities=[candidate()]), record())
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["recognized_positive_targets"], 1)
        self.assertEqual(evidence["positive_advisory_candidates"], 1)

    def test_missing_lockfile_is_not_coverage(self):
        for bad in ({"SchemaVersion": 2, "Results": []},
                    record(target="build.gradle"),
                    record(target="subdir/gradle.lockfile"),
                    record(target="gradle.lockfile.backup")):
            with self.subTest(bad=bad):
                with self.assertRaises(subject.ProbeError):
                    subject.probe(bad, record())

    def test_wrong_package_or_version_cannot_satisfy_positive(self):
        for vuln in (candidate(version="2.24.3"),
                     candidate(package="fake-log4j-core"),
                     candidate(severity="LOW"), {}):
            with self.subTest(vuln=vuln):
                with self.assertRaisesRegex(subject.ProbeError, "did not identify"):
                    subject.probe(record(vulnerabilities=[vuln]), record())

    def test_benign_advisory_is_a_failed_control(self):
        with self.assertRaisesRegex(subject.ProbeError, "benign"):
            subject.probe(record(vulnerabilities=[candidate()]),
                          record(vulnerabilities=[candidate()]))

    def test_malformed_inventory_and_unexpected_analyzer_fail_closed(self):
        for bad in ({"Results": []}, {"SchemaVersion": 2, "Results": "not-list"},
                    {"SchemaVersion": 2, "Results": [{}]},
                    record(analyzer=""),
                    record(analyzer="npm")):
            with self.subTest(bad=bad):
                if bad == record(analyzer="npm"):
                    with self.assertRaisesRegex(subject.ProbeError, "analyzers disagree"):
                        subject.probe(bad, record())
                else:
                    with self.assertRaises(subject.ProbeError):
                        subject.probe(bad, record())

    def test_output_contains_no_dependency_advisory_text(self):
        evidence = subject.probe(record(vulnerabilities=[{
            **candidate(), "Title": "UNTRUSTED_DETAILS_SHOULD_NOT_COPY"
        }]), record())
        self.assertNotIn("UNTRUSTED_DETAILS_SHOULD_NOT_COPY", json.dumps(evidence))


if __name__ == "__main__":
    unittest.main()
