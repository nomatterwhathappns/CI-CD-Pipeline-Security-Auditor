# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Shared, non-executing helpers used by security rules."""

from dataclasses import dataclass, field
from pathlib import Path
import re
import shlex


UNTRUSTED_EXPRESSION = re.compile(
    r"github\.(?:head_ref|event\.(?:pull_request\.(?:title|body|head\.(?:ref|label))"
    r"|issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|discussion\.(?:title|body)|head_commit\.message))\b",
    re.IGNORECASE,
)
EXPRESSION = re.compile(r"\$\{\{[\s\S]*?\}\}")


def untrusted(value):
    return isinstance(value, str) and any(
        UNTRUSTED_EXPRESSION.search(
            re.sub(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"", "''", part[3:-2])
        )
        for part in _expression_strings(value)
    )


def _expression_strings(text):
    """Extract expressions without treating braces inside strings as closers."""
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return
        index, quote = start + 3, None
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if quote == "'" and text[index:index + 2] == "''":
                        index += 2
                        continue
                    quote = None
                elif char == "\\" and quote == '"':
                    index += 1
            elif char in {"'", '"'}:
                quote = char
            elif text[index:index + 2] == "}}":
                cursor = index + 2
                yield text[start:cursor]
                break
            index += 1
        else:
            return


def expressions(value):
    """Walk YAML values safely, including documents containing aliases."""
    seen = set()

    def walk(item, depth=0):
        if depth > 40:
            return
        if isinstance(item, str):
            yield from _expression_strings(item)
        elif isinstance(item, (dict, list)):
            if id(item) in seen:
                return
            seen.add(id(item))
            values = item.values() if isinstance(item, dict) else item
            for child in values:
                yield from walk(child, depth + 1)

    yield from walk(value)


def shell_tokens(script):
    """Tokenize for bounded pattern checks; never execute input scripts."""
    if not isinstance(script, str):
        return []
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars="|&;<>();")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return []


def command_segments(script):
    segments, current = [], []
    for token in shell_tokens(script):
        if token in {"|", "||", "&&", ";", "&"}:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def has_write_permissions(value):
    return value == "write-all" or (
        isinstance(value, dict) and any(permission == "write" for permission in value.values())
    )


@dataclass
class RuleContext:
    path: Path
    workflow: dict
    findings: list = field(default_factory=list)
    ignored: set = field(default_factory=set)
    advisory_data: dict | None = None

    @property
    def event_names(self):
        events = self.workflow.get("on", {})
        if isinstance(events, str):
            return {events}
        if isinstance(events, list):
            return {x for x in events if isinstance(x, str)}
        return set(events) if isinstance(events, dict) else set()

    def jobs(self):
        return self.workflow.get("jobs", {}).items()

    def steps(self, job):
        return enumerate(job.get("steps", []), start=1)

    def env_for(self, job=None, step=None):
        result = {}
        for scope in (self.workflow, job or {}, step or {}):
            env = scope.get("env", {})
            if isinstance(env, dict):
                result.update(env)
        return result

    def source_location(self, job=None, step=None):
        """Return the enclosing YAML scope start, not a shell-token position.

        An alias keeps its anchor's position. Synthetic dictionaries provided
        directly to RuleContext have no source mark and fall back to 1:1.
        """
        scope, kind = self.workflow, "workflow"
        if job is not None:
            jobs = self.workflow.get("jobs", {})
            candidate = jobs.get(job) if isinstance(jobs, dict) else None
            if isinstance(candidate, dict):
                scope, kind = candidate, "job"
                steps = candidate.get("steps", [])
                if (isinstance(step, int) and not isinstance(step, bool)
                        and isinstance(steps, list) and 1 <= step <= len(steps)
                        and isinstance(steps[step - 1], dict)):
                    scope, kind = steps[step - 1], "step"
        return {
            "line": getattr(scope, "source_line", 1),
            "column": getattr(scope, "source_column", 1),
            "location_scope": kind,
        }

    def emit(self, rule_id, message, *, job=None, step=None, confidence="high", **extra):
        if rule_id in self.ignored:
            return
        from src.registry import RULES

        rule = RULES[rule_id]
        finding = {
            "rule_id": rule_id,
            "file": str(self.path),
            "job": job,
            "step": step,
            "message": message,
            "severity": rule["severity"],
            "confidence": confidence,
            "remediation": rule["remediation"],
            "source_digest": getattr(self.workflow, "source_digest", None),
            **self.source_location(job, step),
        }
        finding.update(extra)
        self.findings.append(finding)
