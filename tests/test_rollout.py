"""Tests for the safe, opt-in rollout helper (no real GitHub writes)."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


class RolloutTest(unittest.TestCase):
    def run_rollout(self, args, commands=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            gh = fake_bin / "gh"
            gh.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == api && \"$2\" == user/repos* ]]; then\n"
                "  printf 'security-ci\\tmain\\tfalse\\tfalse\\n"
                "example\\tmain\\tfalse\\tfalse\\n"
                "no-tests\\tmain\\tfalse\\tfalse\\n'\n"
                "  exit 0\n"
                "fi\n"
                "exit 1\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            config = root / "commands.json"
            if commands is not None:
                config.write_text(json.dumps(commands), encoding="utf-8")
            params = [str(ROOT / "scripts" / "rollout.sh"), SHA, *args]
            if commands is not None:
                params.append(str(config))
            return subprocess.run(
                ["bash", *params],
                env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]},
                capture_output=True,
                text=True,
                check=False,
            )

    def test_dry_run_only_lists_explicitly_configured_repo(self):
        result = self.run_rollout(
            [""], {"loic31000/example": "python -m unittest discover -s tests"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PLAN loic31000/example", result.stdout)
        self.assertIn("SKIP loic31000/no-tests", result.stdout)
        self.assertNotIn("PLAN loic31000/no-tests", result.stdout)

    def test_apply_requires_test_configuration(self):
        result = self.run_rollout(["--apply"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("Refusing --apply", result.stderr)

    def test_invalid_config_rejected(self):
        result = self.run_rollout(["--apply"], {"loic31000/example": ["npm test"]})
        self.assertEqual(result.returncode, 2)
        self.assertIn("JSON object", result.stderr)


if __name__ == "__main__":
    unittest.main()
