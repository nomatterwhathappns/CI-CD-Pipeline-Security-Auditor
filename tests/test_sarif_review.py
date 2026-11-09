"""Regression cases for portable SARIF fingerprints and unusual source paths."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.auditor import make_report
from src.reporting import to_sarif


ROOT = Path(__file__).resolve().parent.parent


def primary_fingerprint(report, root=ROOT):
    return to_sarif(report, root)["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]


class TestSarifReview(unittest.TestCase):
    def setUp(self):
        self.report = make_report(ROOT / "fixtures/workflows/insecure-example.yml")

    def test_supported_github_fingerprint_key_is_always_present(self):
        finding = self.report["findings"][0]
        finding.pop("fingerprint", None)
        value = primary_fingerprint(self.report)
        self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_unrelated_source_edits_and_line_movements_preserve_sarif_identity(self):
        previous = primary_fingerprint(self.report)
        finding = self.report["findings"][0]
        finding["source_digest"] = "changed whole-file digest"
        finding["fingerprint"] = "changed conservative baseline identity"
        finding["line"] += 10
        self.assertEqual(primary_fingerprint(self.report), previous)
        partial = to_sarif(self.report, ROOT)["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(partial["chaSource/v1"], "changed conservative baseline identity")

    def test_same_relative_source_keeps_identity_across_checkout_locations(self):
        previous = primary_fingerprint(self.report)
        with TemporaryDirectory() as directory:
            relocated = deepcopy(self.report)
            relative = Path(relocated["findings"][0]["file"]).relative_to(ROOT)
            relocated["findings"][0]["file"] = str(Path(directory) / relative)
            self.assertEqual(primary_fingerprint(relocated, Path(directory)), previous)

    def test_distinct_issue_scopes_do_not_share_fingerprints(self):
        previous = primary_fingerprint(self.report)
        for key, value in (("job", "another"), ("step", 10), ("env_variable", "OTHER_TOKEN"),
                           ("service", "another"), ("advisory_id", "GHSA-example")):
            with self.subTest(key=key):
                updated = deepcopy(self.report)
                updated["findings"][0][key] = value
                self.assertNotEqual(primary_fingerprint(updated), previous)

    def test_suppression_arrays_consistent_when_run_has_external_suppression(self):
        suppressed = self.report["findings"].pop()
        suppressed["suppression"] = {"reason": "Reviewed exception", "expires": "2099-01-01"}
        self.report["suppressed_findings"] = [suppressed]
        results = to_sarif(self.report, ROOT)["runs"][0]["results"]
        self.assertEqual(results[0]["suppressions"], [])
        self.assertEqual(results[1]["suppressions"][0]["status"], "accepted")
        self.assertEqual(results[1]["suppressions"][0]["kind"], "external")
        self.assertEqual(results[1]["suppressions"][0]["properties"]["expires"], "2099-01-01")

    def test_filenames_with_uri_significant_characters_are_unambiguous(self):
        finding = self.report["findings"][0]
        finding["file"] = str(ROOT / "path with space/percent%#question?.yml")
        result = to_sarif(self.report, ROOT)["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "path%20with%20space/percent%25%23question%3F.yml")
        self.assertNotIn("?", uri)
        self.assertNotIn("#", uri)

    def test_root_directory_uri_has_one_trailing_slash(self):
        run = to_sarif(self.report, ROOT)["runs"][0]
        self.assertEqual(run["originalUriBaseIds"]["%SRCROOT%"]["uri"], ROOT.as_uri() + "/")
        self.assertEqual(run["invocations"][0]["workingDirectory"]["uri"], ROOT.as_uri() + "/")

    def test_filesystem_root_uses_canonical_file_uri(self):
        filesystem_root = Path(ROOT.anchor)
        run = to_sarif(self.report, filesystem_root)["runs"][0]
        self.assertEqual(run["originalUriBaseIds"]["%SRCROOT%"]["uri"], filesystem_root.as_uri())
        self.assertEqual(run["invocations"][0]["workingDirectory"]["uri"], filesystem_root.as_uri())

    def test_no_raw_source_or_credential_values_are_embedded(self):
        report = make_report(ROOT / "fixtures/rules/CHA004-bad.yml")
        output = json.dumps(to_sarif(report, ROOT))
        self.assertNotIn("DEMO_ONLY_NOT_A_REAL_SECRET", output)
        self.assertNotIn('"snippet"', output)
        self.assertNotIn('"contents"', output)


if __name__ == "__main__":
    unittest.main()
