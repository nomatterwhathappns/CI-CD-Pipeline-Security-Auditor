"""Exercise all bad/good YAML pairs through the normal audit engine.

These are static inputs, deliberately outside .github/workflows. Tests read
workflow files as data and never run commands or invoke referenced actions.
"""

import json
from pathlib import Path
import unittest

from src.engine import collect_findings
from src.registry import RULES, SEVERITIES


EXAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "rules"
MANIFEST = json.loads((EXAMPLES / "manifest.json").read_text(encoding="utf-8"))
EXPECTED_IDS = {f"CHA{number:03d}" for number in range(1, 24)}
FAKE_CREDENTIAL = "DEMO_ONLY_NOT_A_REAL_SECRET"


class TestRuleExamples(unittest.TestCase):
    def test_manifest_covers_every_enabled_rule(self):
        entries = MANIFEST["examples"]
        self.assertEqual(MANIFEST["schema_version"], 1)
        self.assertEqual(set(RULES), EXPECTED_IDS)
        self.assertEqual({entry["rule_id"] for entry in entries}, EXPECTED_IDS)
        self.assertEqual(len(entries), len(RULES))
        expected_files = set()
        for entry in entries:
            rule_id = entry["rule_id"]
            with self.subTest(rule_id=rule_id):
                self.assertEqual(entry["source"], RULES[rule_id]["reference"])
                self.assertTrue(entry["notes"].strip())
                for variant in ("bad", "good"):
                    filename = f"{rule_id}-{variant}.yml"
                    self.assertEqual(entry[variant], filename)
                    path = EXAMPLES / filename
                    self.assertTrue(path.is_file())
                    self.assertNotIn(".github", path.relative_to(EXAMPLES.parents[1]).parts)
                    expected_files.add(filename)
        self.assertEqual({path.name for path in EXAMPLES.glob("*.yml")}, expected_files)


def make_example_test(entry):
    def test(self):
        rule_id = entry["rule_id"]
        ignored = set(RULES) - {rule_id}
        bad_path = EXAMPLES / entry["bad"]
        findings = collect_findings(bad_path, ignored=ignored)
        self.assertGreater(len(findings), 0, f"{rule_id}: bad example was not detected")
        self.assertEqual({finding["rule_id"] for finding in findings}, {rule_id})
        required = {"rule_id", "file", "job", "step", "message", "severity", "confidence", "remediation"}
        for finding in findings:
            self.assertTrue(required <= set(finding))
            self.assertEqual(finding["file"], str(bad_path))
            self.assertEqual(finding["severity"], RULES[rule_id]["severity"])
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIn(finding["confidence"], {"low", "medium", "high"})
            self.assertEqual(finding["remediation"], RULES[rule_id]["remediation"])
            self.assertTrue(finding["message"].strip())
            self.assertTrue(finding["job"] is None or isinstance(finding["job"], str))
            self.assertTrue(finding["step"] is None or isinstance(finding["step"], int))
        serialized = json.dumps({"findings": findings}, ensure_ascii=False)
        self.assertNotIn(FAKE_CREDENTIAL, serialized)
        good_path = EXAMPLES / entry["good"]
        self.assertEqual(
            collect_findings(good_path, ignored=ignored), [],
            f"{rule_id}: good example produced a finding",
        )
        self.assertEqual(
            collect_findings(good_path), [],
            f"{rule_id}: good example produced a finding under the complete rule set",
        )
    test.__name__ = f"test_{entry['rule_id']}_bad_and_good_yaml"
    test.__doc__ = f"{entry['rule_id']}: detect the bad YAML, accept the good YAML, preserve report metadata."
    return test


for _entry in MANIFEST["examples"]:
    _test = make_example_test(_entry)
    setattr(TestRuleExamples, _test.__name__, _test)


if __name__ == "__main__":
    unittest.main()
