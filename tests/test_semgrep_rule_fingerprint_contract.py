"""SHA-pinned cross-run provenance is evidence, not a bypass for Semgrep."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SemgrepFingerprintWorkflowContractTest(unittest.TestCase):
    def test_unapproved_branch_still_exits_before_scanning(self):
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        gated = workflow.split(
            "      - name: Verify exact reviewed Semgrep rules before use", 1
        )[1].split(
            "      - name: Fingerprint exact approved Semgrep rule objects without exporting rules", 1
        )[0]
        self.assertIn("python3 .audit-python-lock/scripts/verify_semgrep_bundle.py", gated)
        self.assertIn('if [[ "$verified" != "true" ]]; then', gated)
        self.assertIn("--mode observed", gated)
        self.assertIn('semgrep-rule-fingerprint.json', gated)
        self.assertIn('echo "::error::The reviewed Semgrep ruleset is unavailable.', gated)
        self.assertRegex(gated, r"(?m)^\s+exit 1\s*$")
        self.assertIn('echo "SEMGREP_CONFIG_PATH=', gated)

    def test_approved_mode_never_replaces_scanner_config(self):
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        approved = workflow.split(
            "      - name: Fingerprint exact approved Semgrep rule objects without exporting rules", 1
        )[1].split(
            "      - name: Compare actual Semgrep YAML and JSON responses without granting trust", 1
        )[0]
        self.assertIn("if: matrix.scanner == 'semgrep'", approved)
        self.assertIn("--mode approved", approved)
        self.assertIn('semgrep-rule-fingerprint.json', approved)
        self.assertIn('--source "$RUNNER_TEMP/semgrep-approved/rules.yaml"', approved)
        self.assertNotIn("SEMGREP_CONFIG_PATH=", approved)
        self.assertNotIn("|| true", approved)
        self.assertLess(workflow.index("Verify exact reviewed Semgrep rules before use"),
                        workflow.index("Fingerprint exact approved Semgrep rule objects"))

    def test_immutable_runtime_script_compared_to_tested_source(self):
        tests = (ROOT / ".github/workflows/report-tests.yml").read_text()
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text()
        self.assertRegex(workflow, r"(?m)^\s+ref: [a-f0-9]{40}$")
        self.assertIn('git show "FETCH_HEAD:scripts/semgrep_ruleset_fingerprint.py"', tests)
        self.assertIn('cmp - scripts/semgrep_ruleset_fingerprint.py', tests)


if __name__ == "__main__":
    unittest.main()
