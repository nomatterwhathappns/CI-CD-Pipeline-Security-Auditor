import copy
import json
from pathlib import Path
import tempfile
import unittest

from src.rules.guards import check, load_advisory_data, validate_advisory_data


class GuardContext:
    """Keep focused rule tests independent of the CLI and registry."""

    def __init__(self, workflow, advisory_data=None):
        self.workflow = workflow
        self.advisory_data = advisory_data
        self.findings = []

    def jobs(self):
        return self.workflow.get("jobs", {}).items()

    def steps(self, job):
        return enumerate(job.get("steps", []), start=1)

    def emit(self, rule_id, message, **extra):
        self.findings.append({"rule_id": rule_id, "message": message, **extra})


def scan(workflow, advisory_data=None):
    context = GuardContext(workflow, advisory_data)
    check(context)
    return context.findings


def condition_findings(condition, at_job=False):
    job = {"steps": [{"run": "echo ok"}]}
    (job if at_job else job["steps"][0])["if"] = condition
    return scan({"jobs": {"build": job}})


def action_findings(reference, advisory_data=None, at_job=False):
    job = {"uses": reference} if at_job else {"steps": [{"uses": reference}]}
    return scan({"jobs": {"build": job}}, advisory_data)


class TestMalformedConditions(unittest.TestCase):
    def test_extra_literals_and_concatenated_expressions_are_flagged(self):
        for condition in (
            "${{ github.actor }} == 'alice'",
            "!${{ github.event.pull_request.draft }}",
            "${{ false }} && ${{ false }}",
            "${{ false }}${{ false }}",
            "${{ env.UNKNOWN }}${{ 'literal' }}",
            "${{ github.actor == 'alice' }} trailing-text",
            "prefix ${{ github.actor == 'alice' }}",
            " ${{ github.actor == 'alice' }}",
            "${{ github.actor == 'alice' }} ",
            "${{ false }}\n",
            "\n ${{ github.actor == 'alice' }} \n",
        ):
            for at_job in (True, False):
                with self.subTest(condition=condition, at_job=at_job):
                    findings = condition_findings(condition, at_job)
                    self.assertEqual([f["rule_id"] for f in findings], ["CHA018"])
                    self.assertEqual(findings[0]["step"], None if at_job else 1)

    def test_valid_implicit_and_explicit_conditions_are_not_flagged(self):
        for condition in (
            "always()", "${{ always() }}", "${{ !cancelled() }}",
            "github.actor == 'alice'", "${{ github.actor == 'alice' }}",
            "${{    github.actor == 'alice'    }}",
            "${{ contains('}}', github.ref) }}",
            "${{ format('It''s }} fine', github.ref) != '' }}",
            "${{ false }}", False, True, None,
            "${{ env.A }}${{ env.B }}", "${{ '' }}${{ '' }}",
            "${{ incomplete", "${{ 'unterminated }}",
        ):
            with self.subTest(condition=condition):
                self.assertEqual(condition_findings(condition), [])

    def test_yaml_block_chomping_and_preserved_whitespace(self):
        from src.engine import load_workflow

        cases = (
            ('if: " ${{ false }}"', True),
            ('if: "${{ false }} "', True),
            ("if: |\n  ${{ false }}", True),
            ("if: >\n  ${{ false }}", True),
            ("if: |+\n  ${{ false }}\n", True),
            ("if: >+\n  ${{ false }}\n", True),
            ("if: |-\n  ${{ false }}", False),
            ("if: >-\n  ${{ false }}", False),
            ("if: |\n  false", False),
            ("if: ${ { not_a_github_expression } }", False),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "condition.yml"
            for source, expected_finding in cases:
                with self.subTest(source=source):
                    yaml_text = (
                        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                        "    steps:\n      - run: echo ok\n        "
                        + source.replace("\n", "\n        ") + "\n"
                    )
                    path.write_text(yaml_text, encoding="utf-8")
                    findings = scan(load_workflow(path))
                    self.assertEqual(bool(findings), expected_finding)
                    if expected_finding:
                        self.assertEqual([finding["rule_id"] for finding in findings], ["CHA018"])

    def test_conditions_are_checked_only_in_actual_if_fields(self):
        text = "${{ false }} extra"
        workflow = {"if": text, "env": {"if": text}, "jobs": {"build": {
            "name": text, "env": {"if": text}, "steps": [{
                "name": text, "run": text, "with": {"if": text},
            }],
        }}}
        self.assertEqual(scan(workflow), [])


class TestSubstringAuthorization(unittest.TestCase):
    def test_string_allowlist_with_user_identity_is_flagged(self):
        for identity in (
            "github.actor", "github.triggering_actor", "github.event.sender.login",
            "github.event.issue.user.login", "github.event.comment.user.login",
            "github.event.pull_request.user.login", "github.event.review.user.login",
        ):
            for wrapper in ("{}", "${{{{ {} }}}}"):
                with self.subTest(identity=identity, wrapper=wrapper):
                    condition = wrapper.format(f"contains('alice,bob', {identity})")
                    findings = condition_findings(condition)
                    self.assertEqual([f["rule_id"] for f in findings], ["CHA019"])

    def test_case_insensitive_function_and_parenthesized_identity(self):
        self.assertEqual(
            [f["rule_id"] for f in condition_findings("success() && CONTAINS('ali''ce,bob', (github.actor))")],
            ["CHA019"],
        )

    def test_array_contains_and_unrelated_contains_are_not_flagged(self):
        for condition in (
            "contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)",
            "${{ contains(github.event.issue.labels.*.name, 'bug') }}",
            "contains('refs/heads/main', github.ref)",
            "contains('alice,bob', 'github.actor')",
            "contains('', github.actor)",
            "github.actor == 'alice' || github.actor == 'bob'",
            "'contains(''alice,bob'', github.actor)'",
            "format('contains(''alice,bob'', github.actor)')",
            "contains('alice,bob', github.actor + '-suffix')",
            "contains(env.ALLOWLIST, github.actor)",
        ):
            with self.subTest(condition=condition):
                self.assertEqual(condition_findings(condition), [])

    def test_job_guard_is_checked_and_run_or_env_text_is_ignored(self):
        condition = "contains('alice,bob', github.actor)"
        self.assertEqual(condition_findings(condition, at_job=True)[0]["step"], None)
        self.assertEqual(scan({"jobs": {"build": {"env": {"if": condition}, "steps": [{
            "run": condition, "with": {"if": condition},
        }]}}}), [])


class TestKnownAdvisories(unittest.TestCase):
    def test_bundled_snapshot_has_sources_and_explicit_limited_coverage(self):
        data = load_advisory_data()
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["checked_at"], "2026-11-02")
        self.assertEqual(len(data["advisories"]), 3)
        self.assertIn("not a complete", data["coverage"])
        self.assertTrue(all(entry["source"].startswith("https://github.com/") for entry in data["advisories"]))

    def test_known_affected_exact_versions(self):
        for reference, advisory_id in (
            ("tj-actions/changed-files@v45.0.7", "GHSA-mrrh-fwg8-r2c3"),
            ("actions/download-artifact@v4.0.0", "GHSA-cxww-7g56-2vh6"),
            ("actions/download-artifact@4.1.2", "GHSA-cxww-7g56-2vh6"),
            ("dawidd6/action-download-artifact@v5.0.0", "GHSA-5xr6-xhww-33m4"),
        ):
            with self.subTest(reference=reference):
                findings = action_findings(reference)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["rule_id"], "CHA020")
                self.assertEqual(findings[0]["advisory_id"], advisory_id)
                self.assertEqual(findings[0]["advisory_match"], "version_range")
                self.assertEqual(findings[0]["confidence"], "medium")

    def test_patched_and_outside_range_versions_do_not_match(self):
        for reference in (
            "tj-actions/changed-files@v46.0.1", "tj-actions/changed-files@v99.0.0",
            "actions/download-artifact@v4.1.3", "actions/download-artifact@v3.0.0",
            "dawidd6/action-download-artifact@v6.0.0",
        ):
            with self.subTest(reference=reference):
                self.assertEqual(action_findings(reference), [])

    def test_unknown_and_ambiguous_references_are_skipped(self):
        for reference in (
            "unknown/action@v4.1.2", "actions/download-artifact@v4",
            "actions/download-artifact@v4.1", "actions/download-artifact@main",
            "actions/download-artifact@v4.1.2-beta.1", "actions/download-artifact@v4.1.2+build",
            "actions/download-artifact@v04.1.2", "actions/download-artifact@" + "a" * 40,
            "actions/download-artifact@" + "9" * 5000 + ".0.0",
            "actions/download-artifact@${{ inputs.version }}", "actions/download-artifact",
            "./actions/download-artifact@v4.1.2", "docker://actions/download-artifact@v4.1.2",
            "actions/download-artifact/unrelated@v4.1.2",
            "dawidd6/action-download-artifact@v5", "tj-actions/changed-files@v45",
        ):
            with self.subTest(reference=reference):
                self.assertEqual(action_findings(reference), [])

    def test_known_malicious_full_sha_and_case_insensitive_repository(self):
        reference = "TJ-ACTIONS/CHANGED-FILES@0E58ED8671D6B60D0890C21B07F8835ACE038E67"
        finding = action_findings(reference)[0]
        self.assertEqual(finding["advisory_match"], "malicious_sha")
        self.assertEqual(finding["confidence"], "high")
        self.assertIn("tags were subsequently restored", finding["message"])
        self.assertIn("documented malicious commit", finding["message"])

    def test_reusable_workflow_uses_is_checked(self):
        findings = action_findings("actions/download-artifact@v4.1.2", at_job=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["job"], "build")
        self.assertIsNone(findings[0]["step"])

    def test_custom_snapshot_can_replace_bundled_entries(self):
        data = load_advisory_data()
        data["advisories"] = []
        self.assertEqual(action_findings("actions/download-artifact@v4.1.2", data), [])
        data["advisories"] = [copy.deepcopy(load_advisory_data()["advisories"][1])]
        data["advisories"][0]["affected_ranges"] = [">=4.0.0,<4.1.3", "=5.0.0"]
        self.assertEqual(len(action_findings("actions/download-artifact@v5.0.0", data)), 1)

    def test_arbitrary_yaml_strings_are_not_advisory_references(self):
        reference = "actions/download-artifact@v4.1.2"
        self.assertEqual(scan({"env": {"uses": reference}, "jobs": {"build": {
            "env": {"uses": reference}, "steps": [{"run": reference, "with": {"uses": reference}}],
        }}}), [])


class TestAdvisoryValidation(unittest.TestCase):
    def test_custom_file_is_loaded_and_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisories.json"
            data = load_advisory_data()
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(load_advisory_data(path), data)

    def test_invalid_metadata_is_rejected_without_payload_in_errors(self):
        payload = "sensitive-payload-marker"
        cases = [None, [], {}, {"schema_version": 2}, {"schema_version": True}]
        for key, value in (("schema_version", True), ("checked_at", payload),
                           ("checked_at", "2026-02-31"), ("coverage", "bad\ntext"),
                           ("advisories", payload)):
            data = copy.deepcopy(load_advisory_data())
            data[key] = value
            cases.append(data)
        for data in cases:
            with self.subTest(data_type=type(data).__name__):
                with self.assertRaises(ValueError) as error:
                    validate_advisory_data(data)
                self.assertNotIn(payload, str(error.exception))

    def test_invalid_entries_and_injection_ranges_are_rejected(self):
        payload = "__import__('os').system('sensitive-payload-marker')"
        for key, value in (
            ("id", payload), ("action", payload), ("action", "../action"),
            ("summary", "bad\ntext"), ("source", "https://example.com/" + payload),
            ("affected_ranges", [payload]), ("affected_ranges", ["<6"]),
            ("affected_ranges", ["<4.1.3 || >=5.0.0"]),
            ("affected_ranges", ["<4.1.3-beta"]), ("affected_ranges", "<4.1.3"),
            ("affected_ranges", ["<" + "9" * 200 + ".0.0"]),
            ("malicious_shas", ["a" * 39]), ("patched_versions", [payload]),
        ):
            data = copy.deepcopy(load_advisory_data())
            data["advisories"][0][key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as error:
                    validate_advisory_data(data)
                self.assertNotIn("sensitive-payload-marker", str(error.exception))
        data = load_advisory_data()
        data["advisories"].append(copy.deepcopy(data["advisories"][0]))
        with self.assertRaises(ValueError):
            validate_advisory_data(data)

    def test_malformed_json_and_invalid_encoding_errors_hide_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisories.json"
            for text in (b'{"sensitive-payload-marker":', b"\xffsensitive-payload-marker"):
                path.write_bytes(text)
                with self.assertRaises(ValueError) as error:
                    load_advisory_data(path)
                self.assertNotIn("sensitive-payload-marker", str(error.exception))

    def test_input_expressions_and_references_are_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            payload = f"__import__('pathlib').Path('{marker}').write_text('executed')"
            self.assertEqual(condition_findings(payload), [])
            self.assertEqual(action_findings("actions/download-artifact@" + payload), [])
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
