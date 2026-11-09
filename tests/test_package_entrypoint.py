"""Exercise the additional installed-package module entry point."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestPackageEntrypoint(unittest.TestCase):
    def test_package_module_produces_same_audit_result(self):
        result = subprocess.run(
            [sys.executable, "-m", "src", "fixtures/workflows/insecure-example.yml", "--format", "json", "--fail-on-findings"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual({item["rule_id"] for item in report["findings"]}, {"CHA001", "CHA002"})
        self.assertFalse(report["errors"])


if __name__ == "__main__":
    unittest.main()
