"""Non-authorizing comparison must not weaken the Semgrep integrity gate."""
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SemgrepRuntimeComparisonContractTest(unittest.TestCase):
    def test_approved_yaml_gate_precedes_optional_observation(self):
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        gate = workflow.index("      - name: Verify exact reviewed Semgrep rules before use")
        observation = workflow.index(
            "      - name: Compare actual Semgrep YAML and JSON responses without granting trust"
        )
        scan = workflow.index("      - name: Analyser avec Semgrep")
        self.assertLess(gate, observation)
        self.assertLess(observation, scan)

        part = workflow[observation: workflow.index(
            "      - name: Installer zizmor avec hachages vérifiés", observation
        )]
        self.assertIn("if: matrix.scanner == 'semgrep'", part)
        self.assertIn("--approved-yaml \"$RUNNER_TEMP/semgrep-approved/rules.yaml\"", part)
        self.assertIn("--observed-json \"$response\"", part)
        self.assertIn("--lock .audit-python-lock/locks/semgrep-security-audit.json", part)
        self.assertIn("--output \"$summary\"", part)
        self.assertIn('response="$RUNNER_TEMP/semgrep-comparison-response.json"', part)
        self.assertIn('summary="$REPORT_DIR/semgrep-rule-comparison.json"', part)
        self.assertIn('semgrep-registry-observation.json', part)
        self.assertIn('semgrep_drift_metadata.py', part)
        self.assertIn('"$response" .audit-python-lock/locks/semgrep-security-audit.json', part)
        self.assertIn('rm -f "$response"', part)
        self.assertIn('status": "INCOMPARABLE"', part)
        self.assertNotIn('echo "SEMGREP_CONFIG_PATH=', part)
        self.assertNotIn("|| true", part)

        gated = workflow[gate:observation]
        self.assertIn("python3 .audit-python-lock/scripts/verify_semgrep_bundle.py", gated)
        self.assertIn('if [[ "$verified" != "true" ]]; then', gated)
        self.assertIn("exit 1", gated)

    def test_comparison_code_is_checked_against_immutable_checkout(self):
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text()
        report_tests = (ROOT / ".github/workflows/report-tests.yml").read_text()
        match = re.search(
            r"(?ms)^\s+- name: Load SHA-pinned non-sensitive Semgrep drift diagnostics\s*.*?^\s+ref:\s+([a-f0-9]{40})\s*$",
            workflow,
        )
        self.assertIsNotNone(match)
        self.assertIn('git show "FETCH_HEAD:scripts/semgrep_ruleset_compare.py"', report_tests)
        self.assertIn('cmp - scripts/semgrep_ruleset_compare.py', report_tests)


if __name__ == "__main__":
    unittest.main()
