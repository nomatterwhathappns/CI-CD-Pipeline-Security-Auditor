import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "workflows"


class TestCLI(unittest.TestCase):
    def run_auditor(self, target, *options):
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "src" / "auditor.py"),
                str(target),
                *options,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_default_returns_zero_even_with_findings(self):
        result = self.run_auditor(
            FIXTURES / "insecure-example.yml"
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("WARNING [GHA001]:", result.stdout)
        self.assertIn("WARNING [GHA002]:", result.stdout)

    def test_option_returns_one_when_findings_exist(self):
        result = self.run_auditor(
            FIXTURES / "insecure-example.yml",
            "--fail-on-findings",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("WARNING [GHA001]:", result.stdout)

    def test_option_returns_zero_without_findings(self):
        result = self.run_auditor(
            FIXTURES / "clean-example.yml",
            "--fail-on-findings",
        )

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("WARNING", result.stdout)
        self.assertIn("0 temuan", result.stdout)

    def test_missing_path_returns_two(self):
        with TemporaryDirectory() as folder:
            missing_path = Path(folder) / "missing.yml"
            result = self.run_auditor(
                missing_path,
                "--fail-on-findings",
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR:", result.stdout)
