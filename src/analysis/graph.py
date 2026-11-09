# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Follow local workflow/composite references within one explicit snapshot.

Remote actions, JavaScript/Docker action bodies, dynamic references, and cycles
remain explicit unresolved coverage. File contents are never returned or run.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath

from src.engine import (
    AuditError, SourceMapping, analyze_workflow_document, load_yaml_document,
    validate_workflow,
)
from src.rules.additional import _definitely_disabled

MAX_DEPTH = 8
MAX_FILES = 100
MAX_CONTEXTS = 200
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CALL_PATHS = 20
MAX_FLOW_PASSES = 8


def _copy_mapping(mapping):
    result = SourceMapping(getattr(mapping, "source_line", 1),
                           getattr(mapping, "source_column", 1))
    result.update(mapping)
    result.source_digest = getattr(mapping, "source_digest", None)
    return result


def _events(workflow):
    events = workflow.get("on", {})
    if isinstance(events, str):
        return {events}
    if isinstance(events, list):
        return {name for name in events if isinstance(name, str)}
    return {name for name in events if isinstance(name, str)} if isinstance(events, dict) else set()


def _safe_path(root, path):
    """Reject observed symlinks and lexical escapes before opening a file."""
    path = Path(path).absolute()
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise AuditError("Referensi lokal berada di luar repo-root.") from None
    if ".." in parts:
        raise AuditError("Referensi lokal tidak boleh memakai segmen '..'.")
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise AuditError("Referensi lokal melewati symlink yang tidak diperiksa.")
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError, RuntimeError):
        raise AuditError("Referensi lokal tidak dapat dibatasi ke repo-root.") from None
    return path


def _composite_workflow(document, event_names):
    runs = document.get("runs")
    if not isinstance(runs, dict) or not isinstance(runs.get("using"), str):
        raise AuditError("Metadata action harus memiliki runs.using berupa teks.")
    if runs["using"].lower() != "composite":
        return None
    steps = runs.get("steps")
    if not isinstance(steps, list) or not steps:
        raise AuditError("Composite action harus memiliki daftar runs.steps yang tidak kosong.")
    workflow = _copy_mapping(document)
    workflow.clear()
    workflow["on"] = sorted(event_names)
    workflow["outputs"] = document.get("outputs", {})
    workflow.analysis_kind = "composite"
    # Composite steps have their own declaration positions. No caller env or
    # token permissions are copied into this synthetic workflow declaration.
    job = _copy_mapping(runs)
    job.clear()
    job["steps"] = steps
    workflow["jobs"] = {"composite": job}
    return validate_workflow(workflow)


def _local_reference(root, uses, kind):
    if not isinstance(uses, str) or "${{" in uses:
        return None, "dynamic_reference"
    if not uses.startswith(("./", "$/")):
        return None, "container_image" if uses.startswith("docker://") else "remote_reference"
    relative = uses[2:]
    parts = PurePosixPath(relative).parts
    if (not relative or "\\" in relative or "\x00" in relative or "@" in relative
            or PurePosixPath(relative).is_absolute() or ".." in parts
            or PurePosixPath(relative).as_posix() != relative):
        raise AuditError("Bentuk referensi lokal tidak valid atau tidak didukung.")
    candidate = _safe_path(root, root / relative)
    if kind == "workflow":
        # Local reusable workflows live directly in this workflow directory.
        if len(parts) != 3 or parts[:2] != (".github", "workflows") or candidate.suffix.lower() not in {".yml", ".yaml"}:
            raise AuditError("Reusable workflow lokal harus berupa file langsung di .github/workflows.")
        return candidate, None
    if candidate.is_file():
        raise AuditError("Referensi action lokal harus menunjuk ke folder action.")
    first, second = candidate / "action.yml", candidate / "action.yaml"
    for path in (first, second):
        _safe_path(root, path)
    if first.is_file():
        return first, None
    if second.is_file():
        return second, None
    raise AuditError("Metadata action lokal action.yml/action.yaml tidak ditemukan.")


def analyze_graph(entry_paths, repo_root, ignored=None, advisory_data=None):
    """Analyze local documents and caller input contexts with hard limits.

    Counts refer to unique documents; a document can be analyzed under several
    caller-taint contexts. No claim is made about remote/runtime code coverage.
    """
    output = {"findings": [], "errors": [], "files_analyzed": [], "unresolved": [],
              "edges": [], "source_digests": {}, "dataflow_limits": {},
              "limits": {"max_depth": MAX_DEPTH, "max_files": MAX_FILES,
                         "max_contexts": MAX_CONTEXTS, "max_total_bytes": MAX_TOTAL_BYTES,
                         "max_flow_passes": MAX_FLOW_PASSES}}
    requested_root = Path(repo_root).absolute()
    try:
        if requested_root.is_symlink() or not requested_root.is_dir():
            raise AuditError("repo-root harus berupa folder asli yang dapat dibaca.")
        root = requested_root.resolve()
    except (OSError, RuntimeError, AuditError):
        output["errors"].append({"file": str(repo_root), "message": "repo-root tidak valid atau tidak dapat diakses."})
        return output
    parsed, contexts, active, budget = {}, {}, [], [0]
    unique_errors, unique_unresolved, unique_edges = set(), set(), set()
    merged_findings = {}

    def error(path, message):
        key = str(path), message
        if key not in unique_errors:
            unique_errors.add(key)
            output["errors"].append({"file": str(path), "message": message})

    def unresolved(path, job, step, kind, reason):
        item = {"file": str(path), "job": job, "step": step, "kind": kind, "reason": reason}
        key = json.dumps(item, sort_keys=True, ensure_ascii=True)
        if key not in unique_unresolved:
            unique_unresolved.add(key)
            output["unresolved"].append(item)

    def edge(source, target, kind, job, step):
        item = {"from": str(source), "to": str(target), "kind": kind, "job": job, "step": step}
        key = json.dumps(item, sort_keys=True, ensure_ascii=True)
        if key not in unique_edges:
            unique_edges.add(key)
            output["edges"].append(item)

    def read(path):
        if path in parsed:
            return parsed[path]
        if len(parsed) >= MAX_FILES:
            raise AuditError("Batas jumlah dokumen analisis lintas file tercapai.")
        if path.suffix.lower() not in {".yml", ".yaml"}:
            raise AuditError("Analisis lintas file hanya membaca dokumen YAML.")
        try:
            size = path.stat().st_size
        except OSError:
            raise AuditError("Dokumen lokal tidak dapat dibaca.") from None
        if budget[0] + size > MAX_TOTAL_BYTES:
            raise AuditError("Batas total ukuran dokumen analisis lintas file tercapai.")
        document = load_yaml_document(path)
        parsed[path] = document
        budget[0] += size
        output["source_digests"][str(path)] = document.source_digest
        return document

    def add_findings(findings, call_path):
        for finding in findings:
            # Distinct dataflow traces stay distinct; repeated ordinary static
            # issues are merged while retaining the paths that reached them.
            key = json.dumps(finding, sort_keys=True, ensure_ascii=True)
            trace = list(call_path)
            if key in merged_findings:
                previous = merged_findings[key]
                if trace not in previous["analysis_call_paths"] and len(previous["analysis_call_paths"]) < MAX_CALL_PATHS:
                    previous["analysis_call_paths"].append(trace)
                continue
            recorded = dict(finding)
            recorded["analysis_call_path"] = trace
            recorded["analysis_call_paths"] = [trace]
            merged_findings[key] = recorded
            output["findings"].append(recorded)

    def visit(path, expected_kind="workflow", event_names=None, input_sources=None,
              env_sources=None, call_path=()):
        pushed = False
        try:
            path = _safe_path(root, path)
            if len(active) > MAX_DEPTH:
                raise AuditError("Batas kedalaman referensi analisis lintas file tercapai.")
            if path in active:
                unresolved(path, None, None, "cycle", "Referensi lokal membentuk siklus; jalur ini tidak dianalisis ulang.")
                return {}
            document = read(path)
            if expected_kind == "action":
                workflow = _composite_workflow(document, event_names or set())
                if workflow is None:
                    unresolved(path, None, None, "action_implementation", "Implementasi action JavaScript/Docker tidak dianalisis oleh mode ini.")
                    return {}
            else:
                workflow = validate_workflow(document)
                if event_names is not None:
                    if "workflow_call" not in _events(workflow):
                        raise AuditError("Tujuan reusable workflow tidak mendeklarasikan workflow_call.")
                    declaration = workflow.get("on", {})
                    declaration = declaration.get("workflow_call", {}) if isinstance(declaration, dict) else {}
                    workflow = _copy_mapping(workflow)
                    workflow.analysis_workflow_call = declaration
                    workflow["on"] = sorted(event_names)
            events = _events(workflow)
            signature = json.dumps([str(path), expected_kind, sorted(events), input_sources or {}, env_sources or {}],
                                   sort_keys=True, ensure_ascii=True)
            signature = hashlib.sha256(signature.encode()).hexdigest()
            if signature in contexts:
                cached = contexts[signature]
                if cached is not None:
                    add_findings(cached["findings"], (*call_path, str(path)))
                    return cached["outputs"]
                return {}
            if len(contexts) >= MAX_CONTEXTS:
                raise AuditError("Batas konteks pemanggilan analisis lintas file tercapai.")
            contexts[signature] = None
            active.append(path)
            pushed = True
            trace = (*call_path, str(path))
            call_outputs, collected = {}, []
            for pass_number in range(MAX_FLOW_PASSES):
                findings, flow = analyze_workflow_document(path, workflow, ignored=ignored,
                                                           advisory_data=advisory_data,
                                                           input_sources=input_sources,
                                                           env_sources=env_sources,
                                                           call_output_sources=call_outputs)
                output["dataflow_limits"] = flow.get("limits", {})
                if str(path) not in output["files_analyzed"]:
                    output["files_analyzed"].append(str(path))
                collected.extend(findings)
                add_findings(findings, trace)
                for issue in flow.get("unresolved", []):
                    unresolved(path, issue.get("job"), issue.get("step"),
                               issue.get("kind", "dataflow_unknown"), issue.get("reason", "Analisis alur data belum lengkap."))
                calls = {(call.get("job"), call.get("step")): call
                         for call in flow.get("calls", []) if isinstance(call, dict)}
                updated_outputs = {}
                for name, job in workflow["jobs"].items():
                    if _definitely_disabled(job):
                        continue
                    references = [(None, job["uses"], "workflow")] if job.get("uses") else []
                    references += [(number, step["uses"], "action")
                                   for number, step in enumerate(job.get("steps", []), 1)
                                   if step.get("uses") and not _definitely_disabled(step)]
                    for number, uses, kind in references:
                        try:
                            target, problem = _local_reference(root, uses, kind)
                        except (OSError, ValueError) as caught:
                            message = str(caught) if isinstance(caught, AuditError) else "Referensi lokal tidak dapat diperiksa."
                            error(path, message)
                            unresolved(path, name, number, "invalid_local_reference", message)
                            continue
                        if problem:
                            reasons = {
                                "dynamic_reference": "Referensi dinamis tidak dapat ditentukan secara statis.",
                                "remote_reference": "Implementasi referensi remote tidak diambil; cakupannya belum dapat dipastikan.",
                                "container_image": "Isi image action Docker tidak dianalisis oleh mode ini.",
                            }
                            unresolved(path, name, number, problem, reasons[problem])
                            continue
                        edge(path, target, kind, name, number)
                        binding = calls.get((name, number), {})
                        exports = visit(target, expected_kind=kind, event_names=events,
                                        input_sources=binding.get("inputs", {}),
                                        env_sources=binding.get("env_sources", {}) if kind == "action" else None,
                                        call_path=trace)
                        if exports:
                            updated_outputs[(name, number)] = exports
                if updated_outputs == call_outputs:
                    break
                call_outputs = updated_outputs
            else:
                unresolved(path, None, None, "flow_pass_limit", "Batas pengulangan penelusuran output antarpanggilan tercapai.")
            exported = flow.get("workflow_outputs", {})
            contexts[signature] = {"findings": collected, "outputs": exported}
            return exported
        except (OSError, UnicodeError, ValueError, RuntimeError) as caught:
            message = str(caught) if isinstance(caught, AuditError) else "Dokumen lokal gagal dianalisis; periksa struktur dan aksesnya."
            error(path, message)
            return {}
        finally:
            if pushed and active and active[-1] == path:
                active.pop()

    for entry in entry_paths:
        visit(Path(entry))
    output["files_analyzed"].sort()
    output["contexts_analyzed"] = len(contexts)
    output["total_source_bytes"] = budget[0]
    return output
