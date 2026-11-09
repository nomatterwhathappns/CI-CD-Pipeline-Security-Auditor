# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Static checks for conditional guards and a small, offline advisory snapshot.

Advisory schema 1 uses top-level schema_version, checked_at, coverage and
advisories. Each advisory has id, action, summary, source, affected_ranges,
patched_versions and malicious_shas; notes is optional. Range entries are ORed;
comma-separated stable-semver comparisons within an entry are ANDed. Version
matching accepts only exact X.Y.Z references (with optional v), never moving
major/minor tags, prereleases, arbitrary expressions or unknown commit hashes.
Nothing in a workflow or advisory file is evaluated or executed.
"""

from datetime import date
import json
from pathlib import Path
import re


_VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\Z")
_COMPARISON = re.compile(r"\s*(<=|>=|<|>|=)?\s*(v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\s*\Z")
_IDENTITY = re.compile(
    r"github\.(?:actor|triggering_actor|event\.(?:sender\.login|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*user\.login))\Z", re.IGNORECASE
)
_BUNDLED = Path(__file__).resolve().parents[1] / "data" / "advisories.json"
MAX_ADVISORY_BYTES = 5 * 1024 * 1024


def _expression_parts(value):
    """Return expression interiors and literal text, respecting quoted braces."""
    parts, literals, cursor = [], [], 0
    while True:
        start = value.find("${{", cursor)
        if start == -1:
            literals.append(value[cursor:])
            return parts, "".join(literals)
        literals.append(value[cursor:start])
        index, quoted = start + 3, False
        while index < len(value):
            if value[index] == "'":
                if quoted and value[index:index + 2] == "''":
                    index += 2
                    continue
                quoted = not quoted
            if not quoted and value[index:index + 2] == "}}":
                parts.append(value[start + 3:index])
                cursor = index + 2
                break
            index += 1
        else:
            # Incomplete expression syntax is not proof of an always-true guard.
            return [], ""


def _tokens(value):
    """A minimal lexer, used for pattern checks rather than expression evaluation."""
    result, index = [], 0
    while index < len(value):
        char = value[index]
        if char.isspace():
            index += 1
        elif char == "'":
            index += 1
            literal = []
            while index < len(value):
                if value[index] == "'":
                    if value[index:index + 2] == "''":
                        literal.append("'")
                        index += 2
                        continue
                    index += 1
                    result.append(("string", "".join(literal)))
                    break
                literal.append(value[index])
                index += 1
            else:
                return []
        elif char.isalpha() or char == "_":
            start = index
            while index < len(value) and (value[index].isalnum() or value[index] in "_-"):
                index += 1
            result.append(("name", value[start:index]))
        else:
            result.append(("symbol", char))
            index += 1
    return result


def _call_arguments(tokens, start):
    arguments, current, depth = [], [], 0
    for token in tokens[start:]:
        if token == ("symbol", ")") and depth == 0:
            return arguments + [current]
        if token == ("symbol", ",") and depth == 0:
            arguments.append(current)
            current = []
            continue
        if token[0] == "symbol":
            if token[1] in "([":
                depth += 1
            elif token[1] in ")]":
                depth -= 1
                if depth < 0:
                    return []
        current.append(token)
    return []


def _substring_authorization(value):
    parts, _ = _expression_parts(value)
    # A condition without expression delimiters is already an expression in if:.
    for expression in parts if "${{" in value else [value]:
        tokens = _tokens(expression)
        for index, token in enumerate(tokens[:-1]):
            if token[0] != "name" or token[1].lower() != "contains":
                continue
            if tokens[index + 1] != ("symbol", "("):
                continue
            arguments = _call_arguments(tokens, index + 2)
            if len(arguments) != 2 or len(arguments[0]) != 1:
                continue
            search = arguments[0][0]
            if search[0] != "string" or not search[1]:
                continue
            subject = arguments[1]
            while len(subject) > 2 and subject[0] == ("symbol", "(") and subject[-1] == ("symbol", ")"):
                subject = subject[1:-1]
            if any(kind == "string" for kind, _ in subject):
                continue
            if _IDENTITY.fullmatch("".join(text for _, text in subject)):
                return True
    return False


def _conditions(ctx):
    for job_name, job in ctx.jobs():
        yield job.get("if"), job_name, None
        for number, step in ctx.steps(job):
            yield step.get("if"), job_name, number


def _version(value):
    # Bound integer conversion for attacker-controlled workflow references.
    match = _VERSION.fullmatch(value) if isinstance(value, str) and len(value) <= 128 else None
    return tuple(int(part) for part in match.groups()) if match else None


def _comparisons(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("Invalid advisory affected_ranges.")
    result = []
    for part in value.split(","):
        match = _COMPARISON.fullmatch(part)
        if not match:
            raise ValueError("Invalid advisory affected_ranges.")
        boundary = _version(match.group(2))
        if boundary is None:
            raise ValueError("Invalid advisory affected_ranges.")
        result.append((match.group(1) or "=", boundary))
    return result


def _in_range(version, value):
    for operator, boundary in _comparisons(value):
        if not {"<": version < boundary, "<=": version <= boundary,
                ">": version > boundary, ">=": version >= boundary,
                "=": version == boundary}[operator]:
            return False
    return True


def _plain_text(value, maximum=2000):
    return isinstance(value, str) and 0 < len(value) <= maximum and all(
        char.isprintable() for char in value
    )


def validate_advisory_data(data):
    """Validate schema 1. Errors never include untrusted values or file contents."""
    required = {"schema_version", "checked_at", "coverage", "advisories"}
    if not isinstance(data, dict) or set(data) != required or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Invalid advisory snapshot schema; expected schema_version 1.")
    checked_at = data["checked_at"]
    if not isinstance(checked_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", checked_at):
        raise ValueError("Invalid advisory checked_at date.")
    try:
        date.fromisoformat(checked_at)
    except ValueError:
        raise ValueError("Invalid advisory checked_at date.") from None
    if not _plain_text(data["coverage"]) or not isinstance(data["advisories"], list):
        raise ValueError("Invalid advisory snapshot metadata.")
    entry_keys = {"id", "action", "summary", "source", "affected_ranges", "patched_versions", "malicious_shas"}
    seen = set()
    for entry in data["advisories"]:
        if not isinstance(entry, dict) or not entry_keys <= set(entry) or set(entry) - entry_keys - {"notes"}:
            raise ValueError("Invalid advisory entry fields.")
        advisory_id, action = entry["id"], entry["action"]
        if not isinstance(advisory_id, str) or not _GHSA.fullmatch(advisory_id):
            raise ValueError("Invalid advisory id.")
        if not isinstance(action, str) or len(action) > 256 or not _ACTION.fullmatch(action) or any(part in {".", ".."} for part in action.split("/")):
            raise ValueError("Invalid advisory action.")
        key = advisory_id, action.lower()
        if key in seen:
            raise ValueError("Duplicate advisory entry.")
        seen.add(key)
        source = entry["source"]
        if not isinstance(source, str) or not re.fullmatch(
            r"https://github\.com/(?:advisories/|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories/)" + re.escape(advisory_id), source
        ):
            raise ValueError("Invalid advisory source; use a matching GitHub advisory URL.")
        if not _plain_text(entry["summary"], 500) or ("notes" in entry and not _plain_text(entry["notes"])):
            raise ValueError("Invalid advisory descriptive text.")
        ranges, patched, shas = (entry[name] for name in ("affected_ranges", "patched_versions", "malicious_shas"))
        if not all(isinstance(value, list) for value in (ranges, patched, shas)) or not (ranges or shas):
            raise ValueError("Invalid advisory version metadata.")
        for value in ranges:
            _comparisons(value)
        if any(not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"v?(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2}", value) for value in patched):
            raise ValueError("Invalid advisory patched_versions.")
        if any(not isinstance(value, str) or not _SHA.fullmatch(value) for value in shas):
            raise ValueError("Invalid advisory malicious_shas.")
    return data


def load_advisory_data(path=None):
    """Read the bundled snapshot or a user supplied JSON file; perform no network I/O."""
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate advisory JSON keys.")
            result[key] = value
        return result

    try:
        with Path(path or _BUNDLED).open("rb") as stream:
            raw = stream.read(MAX_ADVISORY_BYTES + 1)
        if len(raw) > MAX_ADVISORY_BYTES:
            raise ValueError("Advisory file exceeds the 5 MiB limit.")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise ValueError("Advisory file must contain valid UTF-8 JSON.") from None
    return validate_advisory_data(data)


def _check_advisories(ctx):
    data = load_advisory_data() if ctx.advisory_data is None else validate_advisory_data(ctx.advisory_data)
    by_action = {}
    for entry in data["advisories"]:
        by_action.setdefault(entry["action"].lower(), []).append(entry)
    for job_name, job in ctx.jobs():
        references = [(None, job.get("uses"))]
        references.extend((number, step.get("uses")) for number, step in ctx.steps(job))
        for number, uses in references:
            if not isinstance(uses, str) or uses.startswith(("./", "docker://")):
                continue
            action, separator, reference = uses.rpartition("@")
            if not separator or not _ACTION.fullmatch(action):
                continue
            version = _version(reference)
            for entry in by_action.get(action.lower(), []):
                malicious = bool(_SHA.fullmatch(reference)) and reference.lower() in {sha.lower() for sha in entry["malicious_shas"]}
                matched_range = version is not None and any(_in_range(version, value) for value in entry["affected_ranges"])
                if not malicious and not matched_range:
                    continue
                explanation = "matches a documented malicious commit" if malicious else "matches an advisory version range; review the advisory and its affected configuration"
                message = f"{entry['action']} {explanation}: {entry['id']}."
                if entry["patched_versions"]:
                    message += " Published patched version(s): " + ", ".join(entry["patched_versions"]) + "."
                if entry.get("notes"):
                    message += " " + entry["notes"]
                ctx.emit(
                    "CHA020", message, job=job_name, step=number,
                    confidence="high" if malicious else "medium",
                    advisory_id=entry["id"], advisory_url=entry["source"],
                    advisory_checked_at=data["checked_at"],
                    advisory_match="malicious_sha" if malicious else "version_range",
                )


def check(ctx):
    """Apply CHA018, CHA019 and CHA020 to actual workflow execution fields."""
    for value, job_name, number in _conditions(ctx):
        if not isinstance(value, str):
            continue
        expressions, literal = _expression_parts(value)
        literal_output = any(
            len(tokens := _tokens(expression)) == 1
            and ((tokens[0][0] == "string" and bool(tokens[0][1]))
                 or (tokens[0][0] == "name" and tokens[0][1].lower() in {"true", "false"}))
            for expression in expressions
        )
        # The runner preserves whitespace outside expression delimiters as
        # literal format() segments. Even a space/newline makes output nonempty.
        if expressions and (literal or (len(expressions) > 1 and literal_output)):
            ctx.emit(
                "CHA018", "if: combines expression output with literal text (including whitespace) or another expression, producing a nonempty string instead of a Boolean guard. Put the entire condition inside one expression without surrounding whitespace.",
                job=job_name, step=number,
            )
        if _substring_authorization(value):
            ctx.emit(
                "CHA019", "if: uses contains() on a literal string to authorize an actor or user login. Substring matching can accept partial names; use exact equality or contains(fromJSON('[\"alice\",\"bob\"]'), github.actor).",
                job=job_name, step=number,
            )
    _check_advisories(ctx)
