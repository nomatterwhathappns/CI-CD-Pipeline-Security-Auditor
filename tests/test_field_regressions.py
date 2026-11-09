# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""CHA004 regressions derived from public workflows, never executed.

Primary provenance: cli/cli, .github/workflows/dependabot-triage.lock.yml
blob 4353c564892e9a2bd9290abb25e0fde83783fb7b (metadata at lines 1120,
1916, 1934, 1952, 2123), and issue-triage.lock.yml
blob a9e505555f720773157a217c20fe34ab61b8c41a.
https://api.github.com/repos/cli/cli/git/blobs/4353c564892e9a2bd9290abb25e0fde83783fb7b

These are reduced metadata cases. Passing them measures the corrected
false-positive cases; it does not establish accuracy on the original corpus.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from src.engine import collect_findings


class TestFieldMetadataRegressions(unittest.TestCase):
    def scan_env(self, env, scope="step"):
        workflow = {
            "name": "Reduced public workflow metadata case",
            "on": "workflow_dispatch",
            "jobs": {"check": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo metadata"}]}},
        }
        job = workflow["jobs"]["check"]
        target = {"workflow": workflow, "job": job, "step": job["steps"][0]}[scope]
        target["env"] = env
        with TemporaryDirectory() as folder:
            path = Path(folder) / "metadata.yml"
            path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
            return [finding for finding in collect_findings(path) if finding["rule_id"] == "CHA004"]

    def test_observed_secret_name_lists_are_metadata_at_all_scopes(self):
        values = (
            "GH_AW_GITHUB_MCP_SERVER_TOKEN,GH_AW_GITHUB_TOKEN,GITHUB_TOKEN",
            "GH_AW_DEFAULT_OTLP_ENDPOINT,GH_AW_DEFAULT_OTLP_HEADERS",
        )
        for scope in ("workflow", "job", "step"):
            for value in values:
                with self.subTest(scope=scope, value=value):
                    self.assertEqual(self.scan_env({"GH_AW_SECRET_NAMES": value}, scope), [])

    def test_observed_title_and_provider_are_exact_metadata_literals(self):
        for name, value in (
            ("GH_AW_TOKEN_USAGE_SUMMARY_TITLE", "Threat Detection Token Usage"),
            ("GH_AW_GITHUB_TOKEN_SOURCE", "app"),
        ):
            for scope in ("workflow", "job", "step"):
                with self.subTest(scope=scope, name=name):
                    self.assertEqual(self.scan_env({name: value}, scope), [])

    def test_credential_looking_replacements_are_still_flagged_and_redacted(self):
        marker = "ghp_DEMO_ONLY_NOT_A_REAL_TOKEN_123456789"
        for name in ("GH_AW_SECRET_NAMES", "GH_AW_GITHUB_TOKEN_SOURCE", "GH_AW_TOKEN_USAGE_SUMMARY_TITLE"):
            with self.subTest(name=name):
                findings = self.scan_env({name: marker})
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["env_variable"], name)
                self.assertNotIn(marker, json.dumps(findings))

    def test_malformed_or_single_name_lists_are_not_exempted(self):
        for value in (
            "DEMO_ONLY_NOT_A_REAL_SECRET", "ghp_DEMOtoken", "NAME,ghp_DEMOtoken",
            "ONE-NAME,OTHER_NAME", "NAME,,OTHER_NAME", "NAME, OTHER_NAME",
            "NAME,OTHER_NAME\n", "NAME;OTHER_NAME", "GH_AW_GITHUB_TOKEN", 12345,
        ):
            with self.subTest(value=value):
                self.assertEqual(len(self.scan_env({"GH_AW_SECRET_NAMES": value})), 1)

    def test_metadata_titles_and_providers_do_not_allow_arbitrary_new_values(self):
        for name, value in (
            ("GH_AW_GITHUB_TOKEN_SOURCE", "ghp_DEMO_ONLY_CANDIDATE"),
            ("GH_AW_GITHUB_TOKEN_SOURCE", "APP"),
            ("GH_AW_GITHUB_TOKEN_SOURCE", " app "),
            ("GH_AW_TOKEN_USAGE_SUMMARY_TITLE", "DEMO_ONLY_PRIVATE_VALUE"),
            ("GH_AW_TOKEN_USAGE_SUMMARY_TITLE", "Another token usage title"),
        ):
            with self.subTest(name=name, value=value):
                self.assertEqual(len(self.scan_env({name: value})), 1)

    def test_exemptions_do_not_extend_to_similarly_named_or_actual_credential_keys(self):
        for name, value in (
            ("PROJECT_SECRET_NAMES", "ONE_NAME,OTHER_NAME"),
            ("PROJECT_GITHUB_TOKEN_SOURCE", "app"),
            ("TOKEN_USAGE_SUMMARY_TITLE", "Threat Detection Token Usage"),
            ("gh_aw_secret_names", "ONE_NAME,OTHER_NAME"),
            ("GH_AW_GITHUB_TOKEN", "DEMO_ONLY_CANDIDATE"),
            ("GH_AW_GITHUB_MCP_SERVER_TOKEN", "DEMO_ONLY_CANDIDATE"),
            ("SECRET_GH_AW_DEFAULT_OTLP_HEADERS", "DEMO_ONLY_CANDIDATE"),
        ):
            with self.subTest(name=name):
                self.assertEqual(len(self.scan_env({name: value})), 1)


if __name__ == "__main__":
    unittest.main()
