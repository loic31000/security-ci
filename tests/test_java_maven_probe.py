"""Synthetic adversarial checks; CI additionally runs real Trivy Maven scans."""
import importlib.util
import json
import unittest
from pathlib import Path

script = Path(__file__).resolve().parents[1] / "scripts/java_maven_probe.py"
spec = importlib.util.spec_from_file_location("java_maven_probe", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def report(package=None, path="pom.xml", typ="pom", cls="lang-pkgs"):
    vuln = [] if package is None else [package]
    return {"SchemaVersion": 2, "Results": [
        {"Target": path, "Type": typ, "Class": cls, "Vulnerabilities": vuln}
    ]}


def known(**extra):
    return {"PkgName": "org.apache.logging.log4j:log4j-core",
            "InstalledVersion": "2.14.1", "Severity": "CRITICAL",
            "VulnerabilityID": "CVE-2021-44228", **extra}


class MavenProofTests(unittest.TestCase):
    def test_expected_positive_and_negative(self):
        d = mod.verify(report(known()), report())
        self.assertEqual(d["status"], "PASS")
        self.assertEqual(d["negative_advisory_candidates"], 0)

    def test_missing_target_or_incorrect_analyzer(self):
        for bad in (report(known(), path="backup/pom.xml"),
                    report(known(), path="pom.xml.backup"),
                    report(known(), typ="npm"),
                    report(known(), cls="config"),
                    {"SchemaVersion": 2, "Results": []},
                    {"SchemaVersion": 2, "Results": "unavailable"}):
            with self.subTest(bad=bad):
                with self.assertRaises(mod.MavenEvidenceError):
                    mod.verify(bad, report())

    def test_missing_or_wrong_positive(self):
        for candidate in (None, known(InstalledVersion="2.24.3"),
                          known(PkgName="fake"), known(Severity="LOW")):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(mod.MavenEvidenceError, "missed"):
                    mod.verify(report(candidate), report())

    def test_negative_alert_is_not_clean(self):
        with self.assertRaisesRegex(mod.MavenEvidenceError, "benign"):
            mod.verify(report(known()), report(known()))

    def test_output_excludes_sensitive_untrusted_advisory_description(self):
        d = mod.verify(report(known(Description="PRIVATE_CANDIDATE_DETAILS")), report())
        self.assertNotIn("PRIVATE_CANDIDATE_DETAILS", json.dumps(d))


if __name__ == "__main__":
    unittest.main()
