# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Focused unit cases for CHA004 through CHA010, without executing workflows."""

import json
from pathlib import Path
import unittest

from src.rules.basic import check
from src.rules.common import RuleContext


class RecordingContext(RuleContext):
    """Isolate rule predicates from registry metadata and unrelated checks."""

    def emit(self, rule_id, message, **location):
        if rule_id not in self.ignored:
            self.findings.append({"rule_id": rule_id, "message": message, **location})


def workflow_with_step(run="echo safe", **step_fields):
    return {
        "name": "Rule tests",
        "on": "push",
        "jobs": {
            "example": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": run, **step_fields}],
            }
        },
    }


def scan(workflow, rule_id):
    context = RecordingContext(Path("workflow.yml"), workflow)
    check(context)
    return [finding for finding in context.findings if finding["rule_id"] == rule_id]


class CredentialEnvironmentTests(unittest.TestCase):
    def test_literals_at_all_three_scopes_and_numeric_password(self):
        workflow = workflow_with_step(env={"API_KEY": "step-credential-xyz"})
        workflow["env"] = {"DEPLOY_TOKEN": "root-credential-xyz"}
        workflow["jobs"]["example"]["env"] = {"DB_PASSWORD": 123456789}
        findings = scan(workflow, "CHA004")
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding["level"] for finding in findings}, {"workflow", "job", "step"})
        self.assertEqual(findings[-1]["step"], 1)
        serialized = json.dumps(findings)
        for candidate in ("step-credential-xyz", "root-credential-xyz", "123456789"):
            self.assertNotIn(candidate, serialized)

    def test_blank_dynamic_and_ordinary_values_are_not_credentials(self):
        cases = [
            ("PASSWORD", ""), ("PASSWORD", "   "), ("PASSWORD", None),
            ("PASSWORD", "${{ secrets.DB_PASSWORD }}"),
            ("API_KEY", "${{ vars.API_KEY }}"), ("TOKEN", "$TOKEN"),
            ("TOKEN", "${TOKEN}"), ("PASSWORD", False),
            ("APP_NAME", "auditor"), ("TOKEN_URL", "https://issuer.example/token"),
            ("PRIVATE_KEY_FILE", "/tmp/key"), ("SECRET_ENABLED", True),
            ("MONKEY", "ordinary-value"),
        ]
        for name, value in cases:
            with self.subTest(name=name, value=value):
                self.assertEqual(scan(workflow_with_step(env={name: value}), "CHA004"), [])

    def test_typical_sensitive_variable_names(self):
        for name in ("PASSWORD", "DB_PASSWD", "GITHUB_TOKEN", "CLIENT_SECRET", "APIKEY",
                     "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "SSH_PRIVATE_KEY"):
            with self.subTest(name=name):
                self.assertEqual(len(scan(workflow_with_step(env={name: "candidate"}), "CHA004")), 1)


class ReusableSecretsTests(unittest.TestCase):
    def test_inherit_requires_a_reusable_workflow_call(self):
        for uses in ("./.github/workflows/build.yml", "org/repo/.github/workflows/build.yml@main"):
            with self.subTest(uses=uses):
                workflow = {"jobs": {"call": {"uses": uses, "secrets": "inherit"}}}
                findings = scan(workflow, "CHA005")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["job"], "call")
                self.assertEqual(findings[0]["confidence"], "medium")

    def test_explicit_mapping_and_non_calls_are_not_flagged(self):
        for job in (
            {"uses": "./.github/workflows/build.yml", "secrets": {"token": "${{ secrets.TOKEN }}"}},
            {"uses": "./.github/workflows/build.yml"},
            {"runs-on": "ubuntu-latest", "secrets": "inherit", "steps": []},
        ):
            with self.subTest(job=job):
                self.assertEqual(scan({"jobs": {"example": job}}, "CHA005"), [])

    def test_bulk_serialization_is_reported_once_per_scope(self):
        workflow = workflow_with_step(env={"ALL": "${{ toJSON(secrets) }}"})
        workflow["env"] = {"ALL": "${{ TOJSON ( secrets ) }}"}
        workflow["jobs"]["example"]["env"] = {"ALL": "${{ toJSON(secrets) }}"}
        findings = scan(workflow, "CHA006")
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["level"], "workflow")
        self.assertEqual(findings[-1]["step"], 1)

    def test_only_actual_expression_calls_match(self):
        for value in (
            "Document toJSON(secrets) here", "${{ toJSON(secrets.ONE_SECRET) }}",
            "${{ secrets.TOKEN }}", "${{ 'toJSON(secrets)' }}",
            "${{ contains('toJSON(secrets)', 'secret') }}",
            "${{ format('toJSON({0})', 'secrets') }}",
        ):
            with self.subTest(value=value):
                self.assertEqual(scan(workflow_with_step(env={"VALUE": value}), "CHA006"), [])


class DownloadCommandTests(unittest.TestCase):
    def test_remote_response_piped_to_shell(self):
        scripts = (
            "curl -fsSL https://installer.example/script.sh | bash",
            "curl --url=https://installer.example/script.sh | /bin/sh -s -- arg",
            "curl -fsSL \\\n  https://installer.example/script.sh |\n bash",
            "echo preparation\ncurl https://installer.example/script.sh | sh",
            "wget -qO- https://installer.example/script.sh | bash",
            "wget --output-document=- https://installer.example/script.sh | sh",
            "wget -O - https://installer.example/script.sh | sudo bash",
            "VAR=value command curl https://installer.example/script.sh | bash",
        )
        for script in scripts:
            with self.subTest(script=script):
                findings = scan(workflow_with_step(script), "CHA007")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["step"], 1)

    def test_data_pipes_comments_quoted_examples_and_download_files_do_not_match(self):
        scripts = (
            "curl https://api.example/data | jq .",
            "curl https://installer.example/script.sh -o installer.sh",
            "curl https://installer.example/script.sh -o installer.sh | bash",
            "curl -I https://installer.example/script.sh | bash",
            "curl https://installer.example/script.sh > installer.sh | bash",
            "wget https://installer.example/script.sh | bash",
            "echo 'curl https://installer.example/script.sh | bash'",
            "echo curl https://installer.example/script.sh | bash",
            "# curl https://installer.example/script.sh | bash\necho safe",
            "curl https://installer.example/script.sh '|' bash",
            r"curl https://installer.example/script.sh \| bash",
            "curl file:///tmp/script.sh | bash",
            "curl $SCRIPT_URL | bash",
            "cat <<'EOF'\ncurl https://installer.example/script.sh | bash\nEOF",
            "echo 'multiline example\ncurl https://installer.example/script.sh | bash\n'",
            "curl 'unfinished https://installer.example/script.sh | bash",
        )
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual(scan(workflow_with_step(script), "CHA007"), [])

    def test_tls_disable_flags_and_short_flag_groups(self):
        for script in (
            "curl -k https://download.example/file",
            "curl -fsSkL https://download.example/file",
            "curl --insecure --url https://download.example/file",
            "echo prepare # a comment\ncurl --insecure https://download.example/file",
            "curl --proxy https://proxy.example --insecure https://download.example/file",
            "curl --no-insecure -k https://download.example/file",
            "curl -k https://download.example/a --next https://download.example/b",
        ):
            with self.subTest(script=script):
                self.assertEqual(len(scan(workflow_with_step(script), "CHA008")), 1)

    def test_secure_transfers_and_inert_flag_strings_do_not_match(self):
        for script in (
            "curl --cacert /tmp/ca.pem https://download.example/file",
            "curl -k --no-insecure https://download.example/file",
            "curl -k http://download.example/file",
            "curl https://download.example/-k",
            "curl -H 'X-Example: --insecure' https://download.example/file",
            "curl --proxy https://proxy.example -k http://download.example/file",
            "curl -k http://download.example/a --next https://download.example/b",
            "echo curl --insecure https://download.example/file",
            "echo 'curl --insecure https://download.example/file'",
            "# curl -k https://download.example/file",
        ):
            with self.subTest(script=script):
                self.assertEqual(scan(workflow_with_step(script), "CHA008"), [])

    def test_explicit_non_posix_shell_and_windows_default_are_skipped(self):
        for shell in ("python", "pwsh", "powershell", "cmd", "", 42):
            with self.subTest(shell=shell):
                workflow = workflow_with_step("curl -k https://installer.example/script.sh | bash", shell=shell)
                self.assertEqual(scan(workflow, "CHA007"), [])
                self.assertEqual(scan(workflow, "CHA008"), [])
        workflow = workflow_with_step("curl -k https://installer.example/script.sh | bash")
        workflow["jobs"]["example"]["runs-on"] = "windows-latest"
        self.assertEqual(scan(workflow, "CHA007"), [])
        workflow["jobs"]["example"]["steps"][0]["shell"] = "bash"
        self.assertEqual(len(scan(workflow, "CHA007")), 1)

    def test_shell_defaults_and_override_follow_scope_precedence(self):
        workflow = workflow_with_step("curl -k https://download.example/file")
        workflow["defaults"] = {"run": {"shell": "python"}}
        self.assertEqual(scan(workflow, "CHA008"), [])
        workflow["jobs"]["example"]["defaults"] = {"run": {"shell": "/bin/bash -e {0}"}}
        self.assertEqual(len(scan(workflow, "CHA008")), 1)
        workflow["jobs"]["example"]["steps"][0]["shell"] = "pwsh"
        self.assertEqual(scan(workflow, "CHA008"), [])


class ContainerDependencyTests(unittest.TestCase):
    def test_mutable_job_service_and_docker_action_images(self):
        workflow = workflow_with_step()
        job = workflow["jobs"]["example"]
        job["container"] = "node:22"
        job["services"] = {"db": {"image": "postgres:17"}}
        job["steps"] = [{"uses": "docker://alpine:latest"}]
        findings = scan(workflow, "CHA009")
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["container_type"], "job")
        self.assertEqual(findings[1]["service"], "db")
        self.assertEqual(findings[2]["step"], 1)

    def test_full_digest_is_accepted_and_partial_digest_is_not(self):
        for image in ("node@sha256:" + "a" * 64, "registry.example:5000/app:v1@sha256:" + "B" * 64):
            with self.subTest(image=image):
                workflow = workflow_with_step()
                workflow["jobs"]["example"]["container"] = {"image": image}
                workflow["jobs"]["example"]["services"] = {"db": {"image": image}}
                workflow["jobs"]["example"]["steps"] = [{"uses": "docker://" + image}]
                self.assertEqual(scan(workflow, "CHA009"), [])
        for image in ("node", "node@sha256:abc", "node@sha256:" + "z" * 64):
            with self.subTest(image=image):
                workflow = workflow_with_step()
                workflow["jobs"]["example"]["container"] = image
                self.assertEqual(len(scan(workflow, "CHA009")), 1)

    def test_dynamic_images_are_unresolved_and_regular_actions_are_outside_scope(self):
        for image in ("${{ matrix.image }}", "registry/${{ vars.IMAGE }}", "$IMAGE", "${IMAGE}", "", None):
            with self.subTest(image=image):
                workflow = workflow_with_step()
                workflow["jobs"]["example"]["container"] = {"image": image}
                self.assertEqual(scan(workflow, "CHA009"), [])
        workflow = workflow_with_step()
        workflow["jobs"]["example"]["steps"] = [{"uses": "actions/checkout@v4"}, {"uses": "./local-action"}]
        self.assertEqual(scan(workflow, "CHA009"), [])

    def test_registry_password_candidates_are_never_disclosed(self):
        workflow = workflow_with_step()
        job = workflow["jobs"]["example"]
        job["container"] = {"image": "private/image:1", "credentials": {
            "username": "user", "password": "registry-password-xyz",
        }}
        job["services"] = {"db": {"image": "private/db:1", "credentials": {"password": 987654321}}}
        findings = scan(workflow, "CHA010")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[-1]["service"], "db")
        self.assertNotIn("registry-password-xyz", json.dumps(findings))
        self.assertNotIn("987654321", json.dumps(findings))

    def test_registry_secret_references_and_missing_password_are_not_flagged(self):
        for credentials in (
            {}, {"username": "literal-user"}, {"password": ""}, {"password": None},
            {"password": "${{ secrets.REGISTRY_PASSWORD }}"}, {"password": "$PASSWORD"},
        ):
            with self.subTest(credentials=credentials):
                workflow = workflow_with_step()
                workflow["jobs"]["example"]["container"] = {"image": "private/image:1", "credentials": credentials}
                self.assertEqual(scan(workflow, "CHA010"), [])


if __name__ == "__main__":
    unittest.main()
