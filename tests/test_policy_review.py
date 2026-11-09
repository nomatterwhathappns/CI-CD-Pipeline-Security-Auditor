"""Independent regressions for narrowed exceptions and risk reclassification."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.auditor import main, make_report
from src.policy import fingerprint, load_policy, PolicyError
from src.registry import RULES


class TestPolicyReview(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "policy.json"
        self.baseline = self.root / "baseline.json"

    def workflow(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "on: push\njobs: {build: {steps: [{uses: owner/action@v1}]}}\n",
            encoding="utf-8",
        )
        return path

    def policy(self, pattern):
        self.config.write_text(json.dumps({
            "version": 1,
            "suppressions": [{
                "rule_id": "CHA001", "file": pattern,
                "reason": "Reviewed temporary exception for explicitly scoped files",
                "expires": str(datetime.now(timezone.utc).date() + timedelta(days=30)),
            }],
        }), encoding="utf-8")

    def cli(self, path, *options):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(path), "--format", "json", *map(str, options)])
        return code, json.loads(output.getvalue())

    def test_star_cannot_expand_a_root_exception_into_nested_directories(self):
        self.policy("*.yml")
        root_file = self.workflow("ci.yml")
        nested_file = self.workflow("nested/ci.yml")
        self.assertEqual(make_report(root_file, config_file=self.config)["suppressed_findings_count"], 1)
        self.assertEqual(make_report(nested_file, config_file=self.config)["suppressed_findings_count"], 0)

    def test_named_directory_star_does_not_include_its_subdirectories(self):
        self.policy(".github/workflows/*.yml")
        direct = self.workflow(".github/workflows/ci.yml")
        nested = self.workflow(".github/workflows/nested/ci.yml")
        other = self.workflow("other/ci.yml")
        self.assertEqual(make_report(direct, config_file=self.config)["suppressed_findings_count"], 1)
        for path in (nested, other):
            with self.subTest(path=path):
                self.assertEqual(make_report(path, config_file=self.config)["suppressed_findings_count"], 0)

    def test_globstar_explicitly_matches_zero_or_multiple_directories(self):
        self.policy("**/*.yml")
        for name in ("ci.yml", "nested/ci.yml", "nested/deep/ci.yml", ".github/workflows/ci.yml"):
            with self.subTest(name=name):
                report = make_report(self.workflow(name), config_file=self.config)
                self.assertEqual(report["suppressed_findings_count"], 1)

    def test_globstar_keeps_a_named_prefix_and_suffix(self):
        self.policy(".github/**/ci.yml")
        for name, expected in ((".github/ci.yml", 1), (".github/workflows/deeper/ci.yml", 1),
                               ("other/ci.yml", 0), (".github/workflows/test.yml", 0)):
            with self.subTest(name=name):
                report = make_report(self.workflow(name), config_file=self.config)
                self.assertEqual(report["suppressed_findings_count"], expected)

    def test_question_mark_and_character_class_stay_in_one_component(self):
        self.policy("jobs/[ab]?/ci.yml")
        for name, expected in (("jobs/a1/ci.yml", 1), ("jobs/b2/ci.yml", 1),
                               ("jobs/a/1/ci.yml", 0), ("jobs/c1/ci.yml", 0)):
            with self.subTest(name=name):
                report = make_report(self.workflow(name), config_file=self.config)
                self.assertEqual(report["suppressed_findings_count"], expected)

    def test_repeated_globstars_have_bounded_non_recursive_matching(self):
        # A long but valid pattern must not require recursion/backtracking.
        self.policy("**/" * 150 + "ci.yml")
        report = make_report(self.workflow("one/two/ci.yml"), config_file=self.config)
        self.assertEqual(report["suppressed_findings_count"], 1)

    def test_severity_upgrade_cannot_keep_a_finding_grandfathered(self):
        path = self.workflow("ci.yml")
        code, _ = self.cli(path, "--write-baseline", self.baseline)
        self.assertEqual(code, 0)
        code, report = self.cli(path, "--baseline", self.baseline,
                                "--fail-on-findings", "--fail-on-severity", "high")
        self.assertEqual(code, 0)
        self.assertEqual(report["existing_findings_count"], 1)

        with patch.dict(RULES["CHA001"], severity="critical"):
            code, report = self.cli(path, "--baseline", self.baseline,
                                    "--fail-on-findings", "--fail-on-severity", "high")
        self.assertEqual(code, 1)
        self.assertEqual(report["new_findings_count"], 1)
        self.assertEqual(report["findings"][0]["severity"], "critical")

    def test_confidence_change_requires_review_as_well(self):
        path = self.workflow("ci.yml")
        finding, = make_report(path)["findings"]
        changed = {**finding, "confidence": "medium"}
        self.assertNotEqual(fingerprint(finding, self.root), fingerprint(changed, self.root))

    @unittest.skipUnless(os.name == "posix", "Symlink behavior requires POSIX")
    def test_symlink_loop_in_explicit_policy_or_baseline_is_a_clean_error(self):
        path = self.workflow("ci.yml")
        loop = self.root / "loop.json"
        loop.symlink_to(loop)
        with self.assertRaises(PolicyError):
            load_policy(loop)
        for option in ("--config", "--baseline", "--write-baseline"):
            with self.subTest(option=option):
                code, report = self.cli(path, option, loop)
                self.assertEqual(code, 2)
                self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
