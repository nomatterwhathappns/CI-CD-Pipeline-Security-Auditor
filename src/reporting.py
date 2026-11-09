# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""SARIF 2.1.0 conversion without embedding source or credential values."""

import hashlib
import json
from pathlib import Path
from urllib.parse import quote

from src import __version__
from src.registry import RULES

PROJECT = "https://github.com/nomatterwhathappns/CI-CD-Pipeline-Security-Auditor"


def _level(severity):
    return "error" if severity in {"high", "critical"} else "warning" if severity == "medium" else "note"


def _artifact(path, root):
    resolved = Path(path).resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
        return {"uri": quote(relative, safe="/", errors="surrogatepass"), "uriBaseId": "%SRCROOT%"}
    except ValueError:
        return {"uri": resolved.as_uri()}


def _location_fingerprint(finding, artifact, root=None):
    """Stable, source-free identity for GitHub's supported fingerprint key.

    This identifies a finding within its workflow/job/step scope; it does not
    hash raw source lines or include the whole-file digest used by baselines.
    Reordering steps or changing the identified issue may create a new alert.
    """
    identity = ["cha-location-v1", artifact["uri"], finding["rule_id"],
                finding.get("job"), finding.get("step"), finding["message"],
                finding.get("env_variable"), finding.get("container_type"),
                finding.get("service"), finding.get("advisory_id")]
    if finding.get("analysis_call_path"):
        identity += [[_artifact(path, Path(root or Path.cwd()).resolve())["uri"]
                      for path in finding["analysis_call_path"] if isinstance(path, str)]]
    payload = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def to_sarif(report, root=None):
    root = Path(root or Path.cwd()).resolve()
    directory_uri = root.as_uri()
    if not directory_uri.endswith("/"):
        directory_uri += "/"
    rules = []
    for rule in RULES.values():
        rules.append({
            "id": rule["rule_id"],
            "shortDescription": {"text": rule["title"]},
            "fullDescription": {"text": rule["remediation"]},
            "helpUri": rule["reference"],
            "help": {"text": rule["remediation"]},
            "defaultConfiguration": {"level": _level(rule["severity"])},
            "properties": {"tags": ["security"], "precision": "medium"},
        })
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    results = []
    for finding in report["findings"] + report.get("suppressed_findings", []):
        physical = {"artifactLocation": _artifact(finding["file"], root)}
        if type(finding.get("line")) is int and finding["line"] > 0:
            physical["region"] = {"startLine": finding["line"]}
            if type(finding.get("column")) is int and finding["column"] > 0:
                physical["region"]["startColumn"] = finding["column"]
        result = {
            "ruleId": finding["rule_id"], "ruleIndex": rule_index[finding["rule_id"]],
            "level": _level(finding["severity"]),
            "message": {"text": finding["message"]},
            "locations": [{"physicalLocation": physical}],
            "properties": {"severity": finding["severity"], "confidence": finding["confidence"],
                           "remediation": finding["remediation"], "job": finding.get("job"),
                           "step": finding.get("step"), "locationScope": finding.get("location_scope")},
        }
        result["partialFingerprints"] = {
            "primaryLocationLineHash": _location_fingerprint(finding, physical["artifactLocation"], root)
        }
        trace = finding.get("dataflow_trace", [])
        if isinstance(trace, list) and trace:
            locations = []
            for node in trace[:32]:
                if not isinstance(node, dict) or not isinstance(node.get("file"), str):
                    continue
                physical_node = {"artifactLocation": _artifact(node["file"], root)}
                if type(node.get("line")) is int and node["line"] > 0:
                    physical_node["region"] = {"startLine": node["line"]}
                    if type(node.get("column")) is int and node["column"] > 0:
                        physical_node["region"]["startColumn"] = node["column"]
                locations.append({"location": {"physicalLocation": physical_node,
                                   "message": {"text": f"{node.get('kind', 'flow')}: {node.get('name', 'value')}"}}})
            if locations:
                result["codeFlows"] = [{"threadFlows": [{"locations": locations}]}]
        if finding.get("analysis_call_paths"):
            result["properties"]["analysisCallPaths"] = finding["analysis_call_paths"]
        if finding.get("fingerprint"):
            result["partialFingerprints"]["chaSource/v1"] = finding["fingerprint"]
        if finding.get("baseline_state"):
            result["baselineState"] = "unchanged" if finding["baseline_state"] == "existing" else "new"
        if finding.get("suppression"):
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                        "justification": finding["suppression"]["reason"],
                                        "properties": {"expires": finding["suppression"].get("expires")}}]
        results.append(result)
    if any("suppressions" in result for result in results):
        # SARIF consumers need consistent suppression information for the run.
        for result in results:
            result.setdefault("suppressions", [])
    notifications = [{"level": "error", "message": {"text": error["message"]},
                      "locations": [{"physicalLocation": {"artifactLocation": _artifact(error["file"], root)}}]}
                     for error in report["errors"]]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CHA Auditor", "version": __version__,
                                  "informationUri": PROJECT, "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": directory_uri}},
            "invocations": [{"executionSuccessful": not bool(report["errors"]),
                             "workingDirectory": {"uri": directory_uri},
                             "toolExecutionNotifications": notifications}],
            "results": results,
            "properties": {"filesScanned": report["files_scanned"],
                           "advisorySnapshot": report.get("advisory_snapshot"),
                           "analysis": report.get("analysis")},
        }],
    }
