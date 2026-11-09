"""End-to-end policy behavior: exceptions must be explicit and auditable."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.auditor import main, make_report
from src.policy import PolicyError, load_baseline, load_policy


class TestPolicyReports(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workflow = self.root / "ci.yml"
        self.workflow.write_text("on: push\npermissions: write-all\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
        self.config = self.root / "policy.json"
        self.baseline = self.root / "baseline.json"
        self.today = datetime.now(timezone.utc).date()

    def cli(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(self.workflow), "--format", "json", *map(str, args)])
        return code, json.loads(output.getvalue())

    def policy(self, entries=None, **extra):
        data = {"version": 1, "suppressions": entries or [], **extra}
        self.config.write_text(json.dumps(data), encoding="utf-8")

    def exception(self, **extra):
        return {"rule_id": "CHA001", "file": "ci.yml", "job": "build", "step": 1,
                "reason": "Reviewed compatibility exception", "expires": str(self.today + timedelta(days=30)), **extra}

    def test_scoped_suppression_is_retained_with_reason(self):
        self.policy([self.exception()])
        code, report = self.cli("--config", self.config, "--fail-on-findings")
        self.assertEqual(code, 1)  # workflow write-all is still active
        self.assertEqual([f["rule_id"] for f in report["findings"]], ["CHA003"])
        self.assertEqual(report["suppressed_findings_count"], 1)
        self.assertEqual(report["suppressed_findings"][0]["suppression"]["reason"], "Reviewed compatibility exception")

    def test_exception_does_not_apply_to_another_job_or_step(self):
        for extra in ({"job": "other"}, {"step": 2}, {"file": "elsewhere.yml"}):
            with self.subTest(extra=extra):
                self.policy([self.exception(**extra)])
                _, report = self.cli("--config", self.config)
                self.assertEqual(report["findings_count"], 2)
                self.assertEqual(report["suppressed_findings_count"], 0)

    def test_patterns_relative_to_config_not_terminal(self):
        self.policy([self.exception(file="*.yml")])
        _, report = self.cli("--config", self.config)
        self.assertEqual(report["suppressed_findings_count"], 1)
        external = self.root / "sub" / "policy.json"
        external.parent.mkdir()
        external.write_text(self.config.read_text(), encoding="utf-8")
        _, report = self.cli("--config", external)
        self.assertEqual(report["suppressed_findings_count"], 0)

    def test_expiry_is_inclusive_and_expired_config_fails_closed(self):
        self.policy([self.exception(expires=str(self.today))])
        code, report = self.cli("--config", self.config)
        self.assertEqual(code, 0)
        self.assertEqual(report["suppressed_findings_count"], 1)
        self.policy([self.exception(expires=str(self.today - timedelta(days=1)))])
        code, report = self.cli("--config", self.config)
        self.assertEqual(code, 2)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(report["suppressed_findings_count"], 0)
        self.assertTrue(report["errors"])

    def test_config_global_ignore_combines_with_cli_ignore(self):
        self.policy(ignore=["CHA001"])
        code, report = self.cli("--config", self.config, "--ignore", "CHA003", "--fail-on-findings")
        self.assertEqual(code, 0)
        self.assertEqual(report["rules_ignored"], ["CHA001", "CHA003"])
        self.assertEqual(report["findings_count"], 0)

    def test_config_is_never_automatically_loaded(self):
        self.policy(ignore=["CHA001", "CHA003"])
        _, report = self.cli()
        self.assertEqual(report["findings_count"], 2)

    def test_invalid_configuration_has_sanitized_json_error(self):
        marker = "DEMO_PRIVATE_CONFIG_CONTENT"
        for data in ('{"version":1,"version":1}', '{"version":1,"unknown":"' + marker + '"}',
                     '{"version":true}', "[", '{"version":1,"ignore":["CHA999"]}'):
            with self.subTest(data=data):
                self.config.write_text(data, encoding="utf-8")
                code, report = self.cli("--config", self.config)
                self.assertEqual(code, 2)
                self.assertNotIn(marker, json.dumps(report))

    def test_malformed_suppression_cannot_disable_a_rule(self):
        for extra in ({"file": "../ci.yml"}, {"file": "/ci.yml"}, {"file": "C:\\ci.yml"},
                      {"reason": ""}, {"step": True}, {"step": 0}, {"rule_id": "CHA999"},
                      {"expires": "2099-02-30"}, {"expires": "20990101"}, {"job": "../bad"}):
            with self.subTest(extra=extra):
                self.policy([self.exception(**extra)])
                code, report = self.cli("--config", self.config)
                self.assertEqual(code, 2)
                self.assertTrue(report["errors"])

    def test_baseline_retains_existing_findings_and_only_gates_new(self):
        code, before = self.cli("--write-baseline", self.baseline, "--fail-on-findings")
        self.assertEqual(code, 1)
        self.assertTrue(self.baseline.is_file())
        self.assertEqual(len(load_baseline(self.baseline)), 2)
        code, report = self.cli("--baseline", self.baseline, "--fail-on-findings")
        self.assertEqual(code, 0)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(report["existing_findings_count"], 2)
        self.assertEqual(report["new_findings_count"], 0)
        self.assertTrue(all(f["baseline_state"] == "existing" for f in report["findings"]))
        self.assertEqual(before["findings_count"], report["findings_count"])

    def test_edited_workflow_requires_fresh_review_even_if_rule_unchanged(self):
        self.cli("--write-baseline", self.baseline)
        self.workflow.write_text(self.workflow.read_text() + "# reviewed file changed\n", encoding="utf-8")
        code, report = self.cli("--baseline", self.baseline, "--fail-on-findings")
        self.assertEqual(code, 1)
        self.assertEqual(report["new_findings_count"], 2)

    def test_baseline_from_another_file_cannot_grandfather_findings(self):
        self.cli("--write-baseline", self.baseline)
        other = self.root / "other.yml"
        other.write_text(self.workflow.read_text(), encoding="utf-8")
        self.assertEqual(make_report(other, baseline_file=self.baseline)["existing_findings_count"], 0)

    def test_suppressed_findings_are_not_written_into_baseline(self):
        self.policy([self.exception()])
        self.cli("--config", self.config, "--write-baseline", self.baseline)
        self.assertEqual(len(load_baseline(self.baseline)), 1)

    def test_baseline_error_takes_priority_over_findings(self):
        self.baseline.write_text('{"version":1,"fingerprints":["DEMO_BASELINE_SECRET"]}', encoding="utf-8")
        code, report = self.cli("--baseline", self.baseline, "--fail-on-findings")
        self.assertEqual(code, 2)
        self.assertEqual(report["findings_count"], 2)
        self.assertNotIn("DEMO_BASELINE_SECRET", json.dumps(report))

    def test_baseline_not_created_or_overwritten_after_scan_error(self):
        self.cli("--write-baseline", self.baseline)
        before = self.baseline.read_bytes()
        self.workflow.write_text("jobs: [", encoding="utf-8")
        code, report = self.cli("--write-baseline", self.baseline)
        self.assertEqual(code, 2)
        self.assertEqual(self.baseline.read_bytes(), before)
        missing = self.root / "must-not-exist.json"
        self.cli("--write-baseline", missing)
        self.assertFalse(missing.exists())

    def test_unrelated_json_and_output_symlink_are_not_overwritten(self):
        original = '{"not":"a baseline"}'
        self.baseline.write_text(original, encoding="utf-8")
        code, _ = self.cli("--write-baseline", self.baseline)
        self.assertEqual(code, 2)
        self.assertEqual(self.baseline.read_text(), original)
        link = self.root / "linked.json"
        link.symlink_to(self.baseline)
        code, _ = self.cli("--write-baseline", link)
        self.assertEqual(code, 2)
        self.assertEqual(self.baseline.read_text(), original)

    def test_output_failure_is_reported_as_json_without_traceback(self):
        code, report = self.cli("--write-baseline", self.root / "missing" / "baseline.json")
        self.assertEqual(code, 2)
        self.assertTrue(report["errors"])

    def test_baseline_is_an_explicit_opt_in(self):
        self.cli("--write-baseline", self.baseline)
        code, report = self.cli("--fail-on-findings")
        self.assertEqual(code, 1)
        self.assertEqual(report["existing_findings_count"], 0)

    def test_large_or_deep_configuration_is_a_clean_error(self):
        for text in ("x" * (2 * 1024 * 1024 + 1), "[" * 1500 + "0" + "]" * 1500):
            self.config.write_text(text, encoding="utf-8")
            with self.assertRaises(PolicyError):
                load_policy(self.config)
