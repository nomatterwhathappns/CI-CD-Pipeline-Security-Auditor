import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "workflows"


class TestJsonReport(unittest.TestCase):
    def run_json(self, target, *options):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "src" / "auditor.py"),
                str(target),
                "--format",
                "json",
                *options,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        self.assertEqual(result.stderr, "")

        report = json.loads(result.stdout)

        self.assertIsInstance(report, dict)
        self.assertEqual(
            report["findings_count"],
            len(report["findings"]),
        )

        return result, report

    def test_json_report_contains_findings(self):
        target = FIXTURES / "insecure-example.yml"
        result, report = self.run_json(target)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(report["errors"], [])

        rule_ids = [
            finding["rule_id"]
            for finding in report["findings"]
        ]
        self.assertEqual(rule_ids, ["CHA001", "CHA002"])

        first = report["findings"][0]
        self.assertEqual(first["file"], str(target))
        self.assertEqual(first["job"], "audit")
        self.assertEqual(first["step"], 1)

    def test_json_findings_can_return_status_one(self):
        result, report = self.run_json(
            FIXTURES / "insecure-example.yml",
            "--fail-on-findings",
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(report["errors"], [])

    def test_clean_json_report_returns_zero(self):
        result, report = self.run_json(
            FIXTURES / "clean-example.yml",
            "--fail-on-findings",
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["errors"], [])

    def test_missing_path_returns_json_error(self):
        with TemporaryDirectory() as folder:
            target = Path(folder) / "missing.yml"
            result, report = self.run_json(target)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(report["errors"][0]["file"], str(target))

    def test_invalid_yaml_returns_json_error(self):
        with TemporaryDirectory() as folder:
            target = Path(folder) / "broken.yml"
            target.write_text("jobs: [\n", encoding="utf-8")
            result, report = self.run_json(target)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(report["errors"][0]["file"], str(target))

    def test_error_status_takes_priority_over_findings(self):
        with TemporaryDirectory() as folder:
            directory = Path(folder)
            broken_path = directory / "a-broken.yml"
            valid_path = directory / "b-valid.yml"

            broken_path.write_text("jobs: [\n", encoding="utf-8")
            valid_path.write_text(
                (FIXTURES / "insecure-example.yml").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )

            result, report = self.run_json(
                directory,
                "--fail-on-findings",
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(
            report["errors"][0]["file"],
            str(broken_path),
        )

        for finding in report["findings"]:
            self.assertEqual(finding["file"], str(valid_path))
