# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Bounded, source-preserving taint analysis for GitHub Actions expressions.

Only recognized event data is treated as attacker controlled. Unknown values
are not declared safe: unsupported syntax is recorded separately. No workflow
commands, expressions, scripts, or referenced implementations are executed.
"""

from dataclasses import dataclass
import json
import re

from src.rules.common import UNTRUSTED_EXPRESSION, _expression_strings

MAX_JOBS = 100
MAX_STEPS = 1000
MAX_SCRIPT_LINES = 1000
MAX_EXPRESSION_CHARS = 8192
MAX_TOKENS = 256
MAX_TRACE_NODES = 32
_UNKNOWN = object()
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_ENV_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_BOOLEAN_FUNCTIONS = {"contains", "startswith", "endswith", "success", "failure", "always", "cancelled"}
_PAYLOAD = r'''(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s;|&<>()]+)'''
_TARGET = r'''(?:"\$(?:GITHUB_(?:OUTPUT|ENV)|\{GITHUB_(?:OUTPUT|ENV)\})"|\$(?:GITHUB_(?:OUTPUT|ENV)|\{GITHUB_(?:OUTPUT|ENV)\}))'''
_WRITE = re.compile(r"^\s*(?:echo\s+|printf\s+['\"]%s\\n['\"]\s+)(?P<payload>" + _PAYLOAD + r")\s*>>\s*(?P<target>" + _TARGET + r")\s*(?:#[^\n]*)?$" )
_ASSIGNMENT = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<payload>" + _PAYLOAD + r")\s*$")


@dataclass
class _Value:
    trace: tuple = ()
    literal: object = _UNKNOWN


def _merge(*values):
    nodes, seen = [], set()
    for value in values:
        for node in value.trace:
            identity = tuple(sorted(node.items()))
            if identity not in seen:
                seen.add(identity)
                nodes.append(node)
                if len(nodes) >= MAX_TRACE_NODES:
                    return _Value(tuple(nodes))
    return _Value(tuple(nodes))


def _append(value, node):
    if not value.trace:
        return value
    if len(value.trace) >= MAX_TRACE_NODES:
        # A bound on evidence must not erase the fact that an indirection
        # happened. Keep an origin and the newest hop/sink when truncating.
        return _Value((*value.trace[:MAX_TRACE_NODES - 1], node))
    return _merge(value, _Value((node,)))


def _truth(value):
    if value.literal is _UNKNOWN:
        return None
    return value.literal not in (False, None, 0, "")


def _bindings(values, *, fold_names=True):
    """Accept graph-produced provenance, not arbitrary literal values."""
    result = {}
    if not isinstance(values, dict):
        return result
    for name, trace in values.items():
        if not isinstance(name, str) or not _IDENT.fullmatch(name) or not isinstance(trace, (list, tuple)):
            continue
        nodes = []
        for node in trace[:MAX_TRACE_NODES]:
            if not isinstance(node, dict):
                continue
            safe = {}
            for key in ("file", "job", "step", "kind", "name", "line", "column"):
                item = node.get(key)
                if item is None or isinstance(item, (str, int)) and not isinstance(item, bool):
                    safe[key] = item
            if safe.get("kind") and safe.get("name"):
                nodes.append(safe)
        if nodes:
            result[name.lower() if fold_names else name] = _Value(tuple(nodes))
    return result


def _casefold_value(values, name):
    """Windows expression environment properties use a case-insensitive map."""
    for candidate, value in reversed(list(values.items())):
        if candidate.lower() == name.lower():
            return value
    return _Value()


def _environment_value(value):
    """Environment/output values are strings, including YAML booleans."""
    literal = value.literal
    if literal is _UNKNOWN:
        return value
    if literal is None:
        literal = ""
    elif literal is True:
        literal = "true"
    elif literal is False:
        literal = "false"
    elif not isinstance(literal, str):
        literal = str(literal)
    return _Value(value.trace, literal)


class _ExpressionError(ValueError):
    pass


def _formatted_value(template, arguments):
    """Read escaped braces and numeric placeholders without running format."""
    chosen, rendered, index, complete = [], [], 0, True
    while index < len(template):
        if template[index:index + 2] in {"{{", "}}"}:
            rendered.append(template[index])
            index += 2
        elif template[index] == "{":
            match = re.match(r"\{(\d+)\}", template[index:])
            if match is None or len(match[1]) > 5 or int(match[1]) >= len(arguments):
                raise _ExpressionError()
            value = arguments[int(match[1])]
            chosen.append(value)
            if value.literal is _UNKNOWN:
                complete = False
            else:
                rendered.append(_environment_value(value).literal)
            index += len(match.group())
        elif template[index] == "}":
            raise _ExpressionError()
        else:
            rendered.append(template[index])
            index += 1
    value = _merge(*chosen)
    return _Value(value.trace, "".join(rendered) if complete else _UNKNOWN)


def _tokens(text):
    if len(text) > MAX_EXPRESSION_CHARS:
        raise _ExpressionError()
    result, index = [], 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "'":
            value, index = [], index + 1
            while index < len(text):
                if text[index] == "'":
                    if text[index:index + 2] == "''":
                        value.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(text[index])
                index += 1
            else:
                raise _ExpressionError()
            result.append(("string", "".join(value)))
        elif match := re.match(r"[A-Za-z_][A-Za-z0-9_-]*", text[index:]):
            result.append(("name", match.group()))
            index += len(match.group())
        elif match := re.match(r"-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)", text[index:]):
            token = match.group()
            if len(token) > 64:
                raise _ExpressionError()
            result.append(("number", token))
            index += len(token)
        elif text[index:index + 2] in {"&&", "||", "==", "!=", ">=", "<="}:
            result.append(("symbol", text[index:index + 2]))
            index += 2
        elif char in "!><().[],":
            result.append(("symbol", char))
            index += 1
        else:
            raise _ExpressionError()
        if len(result) > MAX_TOKENS:
            raise _ExpressionError()
    return result


class _Parser:
    def __init__(self, text, reference):
        self.tokens = _tokens(text)
        self.index = 0
        self.reference = reference

    def accept(self, value):
        if self.index < len(self.tokens) and self.tokens[self.index][1] == value:
            self.index += 1
            return True
        return False

    def require(self, value):
        if not self.accept(value):
            raise _ExpressionError()

    def parse(self):
        value = self.or_expression()
        if self.index != len(self.tokens):
            raise _ExpressionError()
        return value

    def or_expression(self):
        value = self.and_expression()
        while self.accept("||"):
            other = self.and_expression()
            truth = _truth(value)
            value = value if truth is True else other if truth is False else _merge(value, other)
        return value

    def and_expression(self):
        value = self.comparison()
        while self.accept("&&"):
            other = self.comparison()
            truth = _truth(value)
            # A falsy source string is empty; a truthy source used only as
            # a condition does not become part of the returned right value.
            value = value if truth is False else other
        return value

    def comparison(self):
        value = self.unary()
        while self.index < len(self.tokens) and self.tokens[self.index][1] in {"==", "!=", ">", "<", ">=", "<="}:
            self.index += 1
            self.unary()
            value = _Value()  # Comparison results are finite booleans.
        return value

    def unary(self):
        if self.accept("!"):
            self.unary()
            return _Value()
        return self.primary()

    def primary(self):
        if self.accept("("):
            value = self.or_expression()
            self.require(")")
            return value
        if self.index >= len(self.tokens):
            raise _ExpressionError()
        kind, text = self.tokens[self.index]
        self.index += 1
        if kind == "string":
            return _Value(literal=text)
        if kind == "number":
            try:
                value = int(text, 16) if "x" in text.lower() else float(text)
            except ValueError:
                raise _ExpressionError() from None
            return _Value(literal=value)
        if kind != "name":
            raise _ExpressionError()
        if text.lower() in {"true", "false", "null"}:
            return _Value(literal={"true": True, "false": False, "null": None}[text.lower()])
        if self.accept("("):
            arguments = []
            if not self.accept(")"):
                while True:
                    arguments.append(self.or_expression())
                    if self.accept(")"):
                        break
                    self.require(",")
            return self.call(text.lower(), arguments)
        parts = [text]
        while self.index < len(self.tokens):
            if self.accept("."):
                if self.index >= len(self.tokens) or self.tokens[self.index][0] != "name":
                    raise _ExpressionError()
                parts.append(self.tokens[self.index][1])
                self.index += 1
            elif self.accept("["):
                if self.index >= len(self.tokens) or self.tokens[self.index][0] != "string":
                    raise _ExpressionError()
                parts.append(self.tokens[self.index][1])
                self.index += 1
                self.require("]")
            else:
                break
        return self.reference(parts)

    @staticmethod
    def call(name, arguments):
        if name in _BOOLEAN_FUNCTIONS or name == "hashfiles":
            return _Value()
        if name == "format" and arguments:
            template = arguments[0]
            if isinstance(template.literal, str):
                return _formatted_value(template.literal, arguments[1:])
            return _merge(*arguments)
        if name == "fromjson" and len(arguments) == 1 and isinstance(arguments[0].literal, str):
            try:
                literal = json.loads(arguments[0].literal)
            except (ValueError, RecursionError):
                raise _ExpressionError() from None
            if literal is None or isinstance(literal, (str, int, float, bool)):
                return _Value(arguments[0].trace, literal)
        if name in {"tojson", "fromjson", "join"}:
            return _merge(*arguments)
        raise _ExpressionError()


class _Analysis:
    def __init__(self, ctx, input_sources, env_sources, call_output_sources):
        self.ctx = ctx
        self.inputs = _bindings(input_sources)
        self.initial_env = _bindings(env_sources, fold_names=False)
        self.call_outputs = call_output_sources if isinstance(call_output_sources, dict) else {}
        self.calls, self.unresolved, self._unknown_seen = [], [], set()
        self.output_maps, self.step_maps = {}, {}

    def node(self, kind, name, job=None, step=None):
        node = {"file": str(self.ctx.path), "job": job, "step": step, "kind": kind, "name": name}
        if hasattr(self.ctx, "source_location"):
            node.update({key: value for key, value in self.ctx.source_location(job, step).items() if key in {"line", "column"}})
        return node

    def unknown(self, kind, job=None, step=None):
        key = (kind, job, step)
        if key not in self._unknown_seen:
            self._unknown_seen.add(key)
            self.unresolved.append({"file": str(self.ctx.path), "job": job, "step": step,
                                    "kind": kind, "reason": "Bentuk atau batas analisis alur data belum didukung; tidak dinyatakan aman."})

    def environment_property(self, env, name, job, step):
        """Follow runner envContext casing without inventing an unknown OS.

        StepsRunner uses a case-insensitive DictionaryContextData on Windows
        and CaseSensitiveDictionaryContextData elsewhere. Labels inferred from
        a known runner are a static approximation, not runtime OS verification.
        """
        definition = self.ctx.workflow.get("jobs", {}).get(job, {})
        runner = definition.get("runs-on", "") if isinstance(definition, dict) else ""
        labels = [runner] if isinstance(runner, str) else runner if isinstance(runner, list) else []
        windows, posix = False, False
        for label in labels:
            if not isinstance(label, str) or "${{" in label:
                continue
            label = label.lower()
            windows |= label == "windows" or label.startswith("windows-")
            posix |= label in {"linux", "macos"} or label.startswith(("ubuntu-", "macos-"))
        if windows and not posix:
            return _casefold_value(env, name)
        if name in env:
            return env[name]
        if not (posix and not windows) and _casefold_value(env, name).trace:
            self.unknown("env-case-unknown", job, step)
        return _Value()

    def value(self, text, env, steps, needs, job=None, step=None, all_jobs=None):
        if not isinstance(text, str):
            return _Value(literal=text if isinstance(text, (bool, int, float)) or text is None else _UNKNOWN)

        def reference(parts):
            canonical = ".".join(parts).lower()
            if all(_IDENT.fullmatch(part) for part in parts) and UNTRUSTED_EXPRESSION.fullmatch(canonical):
                return _Value((self.node("event", canonical, job, step),))
            original_parts = parts
            parts = [part.lower() for part in parts]
            if len(parts) == 2 and parts[0] == "env":
                return self.environment_property(env, original_parts[1], job, step)
            if len(parts) == 2 and parts[0] == "inputs":
                return _append(self.inputs.get(parts[1], _Value()), self.node("input", parts[1], job, step))
            if len(parts) == 4 and parts[0] == "steps" and parts[2] == "outputs":
                return steps.get(parts[1], {}).get(parts[3], _Value())
            if len(parts) == 4 and parts[0] == "needs" and parts[2] == "outputs":
                return needs.get(parts[1], {}).get(parts[3], _Value())
            if all_jobs is not None and len(parts) == 4 and parts[0] == "jobs" and parts[2] == "outputs":
                return all_jobs.get(parts[1], {}).get(parts[3], _Value())
            return _Value()

        values = []
        found = list(_expression_strings(text))
        if not found:
            if "${{" in text:
                self.unknown("unsupported-expression", job, step)
                return _Value()
            return _Value(literal=text)
        cursor = 0
        for expression in found:
            cursor = text.find(expression, cursor) + len(expression)
        if "${{" in text[cursor:]:
            self.unknown("unsupported-expression", job, step)
        for expression in found:
            try:
                values.append(_Parser(expression[3:-2], reference).parse())
            except (ValueError, RecursionError):
                self.unknown("unsupported-expression", job, step)
        value = values[0] if len(values) == 1 and text == found[0] else _merge(*values)
        if len(value.trace) >= MAX_TRACE_NODES:
            self.unknown("trace-limit", job, step)
        return value

    def env_scope(self, scope, inherited, steps, needs, job=None, step=None):
        env = scope.get("env")
        if isinstance(env, str):
            self.unknown("dynamic-env", job, step)
            return {}
        result = dict(inherited)
        if not isinstance(env, dict):
            return result
        # Simultaneous map evaluation avoids inventing same-map aliases and
        # source order that GitHub does not guarantee for env declarations.
        for name, text in env.items():
            if not isinstance(name, str) or not _ENV_IDENT.fullmatch(name):
                continue
            value = self.value(text, inherited, steps, needs, job, step)
            result[name] = _environment_value(_append(value, self.node("env", name, job, step)))
        return result

    def sink(self, script, env, steps, needs, job, number):
        if not isinstance(script, str):
            return
        value = self.value(script, env, steps, needs, job, number)
        # CHA002 covers direct event interpolation. CHA023 requires at least
        # one recognized indirection hop, not just the presence of a source.
        if value.trace and any(node["kind"] != "event" for node in value.trace):
            trace = _append(value, self.node("script", "executable-source", job, number)).trace
            self.ctx.emit("CHA023", "Data tak tepercaya mencapai sumber script melalui env/input/output. Tinjau jalur data dan risiko injeksi.",
                          job=job, step=number, confidence="medium", dataflow_trace=list(trace))

    def shell_payload(self, payload, env, locals_, steps, needs, job, number):
        quoted = len(payload) >= 2 and payload[0] in {"'", '"'} and payload[-1] == payload[0]
        quote = payload[0] if quoted else None
        text = payload[1:-1] if quoted else payload
        value = self.value(text, env, steps, needs, job, number)
        if quote != "'":
            shell = dict(env)
            shell.update(locals_)
            variables = []
            for match in _VARIABLE.finditer(text):
                cursor = match.start() - 1
                while cursor >= 0 and text[cursor] == "\\":
                    cursor -= 1
                if (match.start() - cursor - 1) % 2 == 0:
                    variables.append(match)
            # POSIX variables are case-sensitive even though expression
            # property lookup may be case-insensitive.
            referenced = [shell.get(match.group(1) or match.group(2), _Value()) for match in variables]
            if variables:
                value = _merge(value, *referenced)
        return value, text

    def writes(self, script, env, steps, needs, job, number):
        from src.rules.basic import _posix_step

        definition = self.ctx.workflow["jobs"][job]
        step = definition["steps"][number - 1]
        if not _posix_step(self.ctx, definition, step):
            if "GITHUB_OUTPUT" in script or "GITHUB_ENV" in script:
                self.unknown("unsupported-output-shell", job, number)
            return {}, {}
        if not _simple_output_script(script):
            if "GITHUB_OUTPUT" in script or "GITHUB_ENV" in script:
                self.unknown("unsupported-output-control-flow", job, number)
            return {}, {}
        outputs, additions, locals_ = {}, {}, {}
        lines = script.splitlines()
        if len(lines) > MAX_SCRIPT_LINES:
            self.unknown("script-line-limit", job, number)
        for line in lines[:MAX_SCRIPT_LINES]:
            assignment = _ASSIGNMENT.fullmatch(line)
            if assignment:
                payload = assignment["payload"]
                if "$(" not in payload and "`" not in payload:
                    value, _ = self.shell_payload(payload, env, locals_, steps, needs, job, number)
                    locals_[assignment["name"]] = value
                continue
            write = _WRITE.fullmatch(line)
            if write is None:
                if "GITHUB_OUTPUT" in line or "GITHUB_ENV" in line:
                    self.unknown("unsupported-output-write", job, number)
                continue
            payload = write["payload"]
            if "$(" in payload or "`" in payload:
                self.unknown("unsupported-output-write", job, number)
                continue
            value, text = self.shell_payload(payload, env, locals_, steps, needs, job, number)
            name, separator, literal = text.partition("=")
            destination = additions if "GITHUB_ENV" in write["target"] else outputs
            identifier = _ENV_IDENT if destination is additions else _IDENT
            if not separator or not identifier.fullmatch(name):
                self.unknown("dynamic-output-name", job, number)
                continue
            kind = "env-file" if destination is additions else "step-output"
            if value.literal is not _UNKNOWN:
                value = _Value(value.trace, literal)
            destination[name if destination is additions else name.lower()] = _environment_value(
                _append(value, self.node(kind, name, job, number))
            )
        return outputs, additions

    def call(self, values, env, steps, needs, job, number):
        bindings = {}
        if isinstance(values, dict):
            for name, text in values.items():
                if isinstance(name, str) and _IDENT.fullmatch(name):
                    value = self.value(text, env, steps, needs, job, number)
                    if value.trace:
                        bindings[name] = list(_append(value, self.node("call-input", name, job, number)).trace)
        self.calls.append({"job": job, "step": number, "inputs": bindings,
                           "env_sources": {name: list(value.trace) for name, value in env.items() if value.trace}})

    def run_job(self, name, job, workflow_env):
        from src.rules.additional import _definitely_disabled

        if _definitely_disabled(job):
            self.output_maps[name.lower()] = {}
            self.step_maps[name.lower()] = {}
            return
        dependency_names = job.get("needs", [])
        if isinstance(dependency_names, str):
            dependency_names = [dependency_names]
        dependency_names = dependency_names if isinstance(dependency_names, list) else []
        needs = {key.lower(): self.output_maps.get(key.lower(), {}) for key in dependency_names if isinstance(key, str)}
        env = self.env_scope(job, workflow_env, {}, needs, name)
        outputs = {}
        if job.get("uses"):
            self.call(job.get("with"), env, {}, needs, name, None)
            outputs = _bindings(self.call_outputs.get((name, None)))
            self.output_maps[name.lower()] = {key: _append(value, self.node("call-output", key, name)) for key, value in outputs.items()}
            return
        steps = {}
        for number, step in enumerate(job.get("steps", [])[:MAX_STEPS], 1):
            if _definitely_disabled(step):
                continue
            effective_env = self.env_scope(step, env, steps, needs, name, number)
            command = step.get("run", "")
            self.sink(command, effective_env, steps, needs, name, number)
            if str(step.get("uses", "")).split("@")[0].lower() == "actions/github-script":
                self.sink((step.get("with") or {}).get("script", ""), effective_env, steps, needs, name, number)
            if step.get("uses"):
                self.call(step.get("with"), effective_env, steps, needs, name, number)
            additions = {}
            if isinstance(command, str):
                outputs, additions = self.writes(command, effective_env, steps, needs, name, number)
            if step.get("uses"):
                outputs = {key: _append(value, self.node("call-output", key, name, number))
                           for key, value in _bindings(self.call_outputs.get((name, number))).items()}
            identifier = step.get("id")
            if isinstance(identifier, str) and _IDENT.fullmatch(identifier):
                steps[identifier.lower()] = outputs
            env.update(additions)
        if len(job.get("steps", [])) > MAX_STEPS:
            self.unknown("step-limit", name)
        self.step_maps[name.lower()] = steps
        declared = job.get("outputs", {})
        outputs = {}
        if isinstance(declared, dict):
            for key, text in declared.items():
                if isinstance(key, str) and _IDENT.fullmatch(key):
                    value = self.value(text, env, steps, needs, name)
                    outputs[key.lower()] = _append(value, self.node("job-output", key, name))
        self.output_maps[name.lower()] = outputs

    def run(self):
        workflow = self.ctx.workflow
        jobs = dict(list(workflow.get("jobs", {}).items())[:MAX_JOBS])
        if len(workflow.get("jobs", {})) > MAX_JOBS:
            self.unknown("job-limit")
        env = self.env_scope(workflow, self.initial_env, {}, {})
        pending = dict(jobs)
        completed = set()
        while pending:
            ready = []
            for name, job in pending.items():
                needs = job.get("needs", [])
                needs = [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []
                dependencies = {item for item in needs if isinstance(item, str) and item in jobs}
                if dependencies <= completed:
                    ready.append(name)
            if not ready:
                for name in pending:
                    self.unknown("cyclic-job-dependencies", name)
                # Still inspect each remaining job's own direct sources, without
                # inventing outputs of jobs that have not been analyzed.
                ready = list(pending)
            for name in ready:
                self.run_job(name, pending.pop(name), env)
                completed.add(name)
        exported = {}
        if getattr(workflow, "analysis_kind", None) == "composite":
            declarations = workflow.get("outputs", {})
            local_steps = self.step_maps.get("composite", {})
        else:
            events = workflow.get("on", {})
            call = getattr(workflow, "analysis_workflow_call", None)
            if call is None:
                call = events.get("workflow_call", {}) if isinstance(events, dict) else {}
            declarations = call.get("outputs", {}) if isinstance(call, dict) else {}
            local_steps = {}
        if isinstance(declarations, dict):
            for name, declaration in declarations.items():
                if isinstance(name, str) and _IDENT.fullmatch(name) and isinstance(declaration, dict):
                    value = self.value(declaration.get("value", ""), env, local_steps, {}, all_jobs=self.output_maps)
                    if value.trace:
                        exported[name] = list(_append(value, self.node("workflow-output", name)).trace)
        return {"calls": self.calls, "job_outputs": {
            name: {key: list(value.trace) for key, value in values.items() if value.trace}
            for name, values in self.output_maps.items()}, "workflow_outputs": exported,
            "step_outputs": {name: {identifier: {key: list(value.trace) for key, value in values.items() if value.trace}
                                     for identifier, values in steps.items()} for name, steps in self.step_maps.items()},
            "unresolved": self.unresolved,
            "limits": {"max_jobs": MAX_JOBS, "max_steps_per_job": MAX_STEPS,
                       "max_script_lines": MAX_SCRIPT_LINES,
                       "max_expression_chars": MAX_EXPRESSION_CHARS,
                       "max_expression_tokens": MAX_TOKENS, "max_trace_nodes": MAX_TRACE_NODES}}


def _simple_output_script(script):
    """Only linear, complete single-line quoting is modeled for shell writes.

    Branch/loop bodies and heredocs need a real shell control-flow graph.
    Recording these forms as unresolved avoids inventing unconditional writes
    or output commands embedded inside a multiline quoted example.
    """
    quote, escaped, comment = None, False, False
    for line in script.splitlines():
        # Braced variable references are regular shell data, not command
        # groups. Remove only this recognized shape for the lexical guard.
        line = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "$VARIABLE", line)
        if re.match(r"\s*(?:if|elif|else|fi|for|while|until|do|done|case|esac|function)\b", line):
            return False
        for index, char in enumerate(line):
            if comment:
                break
            if escaped:
                escaped = False
                continue
            if char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == "#":
                comment = True
            elif line[index:index + 2] == "<<":
                return False
            elif char in "();&|{}":
                # Functions, compound commands and grouped writes cannot be
                # treated as unconditional linear output commands.
                return False
        if quote or escaped:
            return False
        comment = False
    return True


def direct_script_source(script):
    """True for supported direct event text, False for known bounded forms.

    None requests the caller's legacy fallback for unsupported syntax. Other
    contexts are not treated as direct event sources; CHA023 follows them.
    """
    if not isinstance(script, str):
        return False
    def reference(parts):
        name = ".".join(parts).lower()
        if all(_IDENT.fullmatch(part) for part in parts) and UNTRUSTED_EXPRESSION.fullmatch(name):
            return _Value(({"kind": "event", "name": name},))
        return _Value()
    unknown = False
    expressions = list(_expression_strings(script))
    if "${{" in script and not expressions:
        return None
    cursor = 0
    for expression in expressions:
        cursor = script.find(expression, cursor) + len(expression)
        try:
            value = _Parser(expression[3:-2], reference).parse()
        except (ValueError, RecursionError):
            unknown = True
            continue
        if value.trace:
            return True
    if "${{" in script[cursor:]:
        unknown = True
    return None if unknown else False


def check(ctx, input_sources=None, env_sources=None, call_output_sources=None):
    """Emit indirect-source findings and return graph binding summaries.

    Graph bindings map an input/environment/output name to a provenance-node
    list, never to a raw value. call_output_sources is keyed by (job, step),
    with step=None for reusable workflow calls. Only graph mode follows files.
    """
    return _Analysis(ctx, input_sources, env_sources, call_output_sources).run()
