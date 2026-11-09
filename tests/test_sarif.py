"""Check useful SARIF locations, suppressed results and scan-failure signaling."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.auditor import main, make_report
from src.reporting import to_sarif
from src.registry import RULES


ROOT = Path(__file__).resolve().parent.parent


class TestSarif(unittest.TestCase):
    def test_rule_metadata_and_location_for_real_workflow(self):
        report = make_report(ROOT / "fixtures/workflows/insecure-example.yml")
        sarif = to_sarif(report, ROOT)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        self.assertEqual({rule["id"] for rule in run["tool"]["driver"]["rules"]}, set(RULES))
        self.assertEqual(len(run["results"]), 2)
        for result in run["results"]:
            location = result["locations"][0]["physicalLocation"]
            self.assertEqual(location["artifactLocation"]["uri"], "fixtures/workflows/insecure-example.yml")
            self.assertEqual(location["artifactLocation"]["uriBaseId"], "%SRCROOT%")
            self.assertGreater(location["region"]["startLine"], 0)
            self.assertTrue(result["partialFingerprints"]["chaSource/v1"])
            self.assertNotIn("snippet", location)

    def test_cli_emits_only_sarif_and_preserves_exit_status(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([str(ROOT / "fixtures/workflows/insecure-example.yml"), "--format", "sarif", "--fail-on-findings"])
        self.assertEqual(status, 1)
        run = json.loads(output.getvalue())["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_failed_scan_is_an_unsuccessful_invocation_with_notifications(self):
        with TemporaryDirectory() as directory:
            report = make_report(Path(directory) / "missing.yml")
            run = to_sarif(report)["runs"][0]
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(run["results"], [])
        self.assertTrue(run["invocations"][0]["toolExecutionNotifications"])

    def test_encoded_paths_and_external_absolute_uri(self):
        report = make_report(ROOT / "fixtures/workflows/insecure-example.yml")
        finding = report["findings"][0]
        finding["file"] = str(ROOT / "workflows/with space#%.yml")
        result = to_sarif(report, ROOT)["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "workflows/with%20space%23%25.yml")
        with TemporaryDirectory() as directory:
            finding["file"] = str(Path(directory) / "external.yml")
            artifact = to_sarif(report, ROOT)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            self.assertTrue(artifact["uri"].startswith("file:///"))
            self.assertNotIn("uriBaseId", artifact)

    def test_suppressions_and_baseline_classification_are_auditable(self):
        report = make_report(ROOT / "fixtures/workflows/insecure-example.yml")
        active = report["findings"][0]
        active["baseline_state"] = "existing"
        suppressed = report["findings"].pop()
        suppressed["suppression"] = {"reason": "Reviewed temporary exception", "expires": "2099-01-01"}
        report["suppressed_findings"] = [suppressed]
        results = to_sarif(report, ROOT)["runs"][0]["results"]
        self.assertEqual(results[0]["baselineState"], "unchanged")
        self.assertEqual(results[1]["suppressions"][0]["kind"], "external")
        self.assertEqual(results[1]["suppressions"][0]["justification"], "Reviewed temporary exception")

    def test_credential_candidates_never_appear_in_sarif(self):
        path = ROOT / "fixtures/rules/CHA004-bad.yml"
        sarif = json.dumps(to_sarif(make_report(path), ROOT))
        self.assertIn("CHA004", sarif)
        self.assertNotIn("DEMO_ONLY_NOT_A_REAL_SECRET", sarif)

    def test_clean_workflow_produces_empty_successful_results(self):
        run = to_sarif(make_report(ROOT / "fixtures/workflows/clean-example.yml"))["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
