"""Read YAML as data and collect findings without executing workflows."""

import hashlib
import re
from pathlib import Path

import yaml
from yaml.events import AliasEvent

from src.rules.common import RuleContext, untrusted

MAX_FILE_BYTES = 2 * 1024 * 1024
JOB_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class AuditError(ValueError):
    """An input error whose message is safe to include in a report."""


class SourceMapping(dict):
    """YAML mapping with a source position kept outside its data keys."""

    def __init__(self, line, column):
        super().__init__()
        self.source_line = line
        self.source_column = column


class WorkflowLoader(yaml.SafeLoader):
    """Safe YAML with true/false booleans and preserved GitHub 'on' keys."""

    def __init__(self, stream):
        super().__init__(stream)
        self._depth = 0
        self._aliases = 0

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            self._aliases += 1
            if self._aliases > 50:
                raise AuditError("YAML memiliki terlalu banyak alias.")
        self._depth += 1
        if self._depth > 50:
            raise AuditError("Susunan YAML terlalu dalam.")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        # SafeLoader.flatten_mapping can exponentially expand a tiny alias graph.
        # GitHub workflows support anchors, but this auditor rejects merge keys.
        if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
            raise AuditError("YAML merge keys (<<) tidak didukung; gunakan pemetaan eksplisit.")
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError:
                raise AuditError("Kunci YAML harus berupa nilai sederhana.") from None
            if duplicate:
                mark = key_node.start_mark
                raise AuditError(f"Kunci YAML berulang pada baris {mark.line + 1}.")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_source_mapping(loader, node):
    # Yield before constructing children, as SafeLoader does, so ordinary
    # anchors (including recursive aliases) retain their original semantics.
    mapping = SourceMapping(node.start_mark.line + 1, node.start_mark.column + 1)
    yield mapping
    mapping.update(loader.construct_mapping(node))


WorkflowLoader.add_constructor(
    "tag:yaml.org,2002:map", _construct_source_mapping
)
WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers
          if tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp"}]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def _validate_env(scope):
    env = scope.get("env")
    if env is None:
        return
    if isinstance(env, str):
        if re.fullmatch(r"\s*\$\{\{[\s\S]+\}\}\s*", env):
            return
        raise AuditError("Bagian env harus berupa pemetaan nama variabel atau ekspresi.")
    if not isinstance(env, dict) or any(not isinstance(key, str) for key in env):
        raise AuditError("Bagian env harus berupa pemetaan nama variabel atau ekspresi.")
    try:
        for key in env:
            key.encode("utf-8")
    except UnicodeError:
        raise AuditError("Nama variabel env mengandung karakter Unicode tidak valid.") from None
    if any(not isinstance(value, (str, int, float, bool, type(None))) for value in env.values()):
        raise AuditError("Nilai env harus berupa teks atau nilai sederhana.")


def load_workflow(path):
    path = Path(path)
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise AuditError("File tidak dapat dibaca.") from None
    if len(data) > MAX_FILE_BYTES:
        raise AuditError("Ukuran file melebihi batas 2 MiB.")
    try:
        workflow = yaml.load(data.decode("utf-8"), Loader=WorkflowLoader)
    except UnicodeError:
        raise AuditError("File bukan teks UTF-8 yang valid.") from None
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" (baris {mark.line + 1}, kolom {mark.column + 1})" if mark else ""
        raise AuditError(f"YAML tidak valid{location}.") from None

    if not isinstance(workflow, dict):
        raise AuditError("Isi workflow harus berupa struktur YAML dengan key.")
    # Bind policy baselines to the very bytes parsed above, without rereading
    # the file or including its potentially sensitive contents in a report.
    workflow.source_digest = hashlib.sha256(data).hexdigest()
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise AuditError("Workflow harus memiliki jobs yang tidak kosong.")
    _validate_env(workflow)
    for job_name, job in jobs.items():
        if not isinstance(job_name, str) or not JOB_ID.fullmatch(job_name):
            raise AuditError("Nama job harus berupa identifier teks yang valid.")
        if not isinstance(job, dict):
            raise AuditError(f"Job {job_name} memiliki format yang salah.")
        if "uses" in job and not isinstance(job["uses"], str):
            raise AuditError(f"Isi uses pada job {job_name} harus berupa teks.")
        if "uses" in job and "steps" in job:
            raise AuditError(f"Job {job_name} tidak boleh menggabungkan uses dan steps.")
        _validate_env(job)
        services = job.get("services", {})
        if not isinstance(services, dict) or any(
            not isinstance(name, str) or not JOB_ID.fullmatch(name)
            or not isinstance(service, dict)
            for name, service in services.items()
        ):
            raise AuditError("Bagian services harus berupa pemetaan identifier service yang valid.")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise AuditError(f"Bagian steps pada job {job_name} harus berupa daftar.")
        if not steps and not isinstance(job.get("uses"), str):
            raise AuditError(f"Job {job_name} harus memiliki steps atau uses.")
        for number, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                raise AuditError(f"Langkah {number} pada job {job_name} tidak valid.")
            _validate_env(step)
            for key in ("run", "uses"):
                if key in step and not isinstance(step[key], str):
                    raise AuditError(f"Isi {key} pada job {job_name}, langkah {number}, harus berupa teks.")
            if step.get("with") is not None and not isinstance(step["with"], dict):
                raise AuditError(f"Bagian with pada job {job_name}, langkah {number}, harus berupa pemetaan.")
    return workflow


def action_is_unpinned(uses):
    if not isinstance(uses, str):
        raise AuditError("Referensi uses harus berupa teks.")
    # GitHub self-repository references resolve to the running workflow's
    # exact commit and do not need a separate @SHA suffix. This check is not
    # a complete validator for uses syntax, as with the existing ./ exemption.
    if not uses or uses.startswith(("./", "$/", "docker://")):
        return False
    _, separator, reference = uses.rpartition("@")
    return not separator or re.fullmatch(r"[0-9a-fA-F]{40}", reference) is None


def _base_rules(ctx):
    if ctx.workflow.get("permissions") == "write-all":
        ctx.emit("CHA003", "permissions: write-all meminta izin tulis luas. Tinjau dan batasi sesuai kebutuhan.")
    for name, job in ctx.jobs():
        if job.get("permissions") == "write-all":
            ctx.emit("CHA003", "permissions: write-all meminta izin tulis luas. Tinjau dan batasi sesuai kebutuhan.", job=name)
        if job.get("uses") and action_is_unpinned(job["uses"]):
            ctx.emit("CHA001", "Reusable workflow belum dipatok ke SHA commit lengkap.", job=name)
        for number, step in ctx.steps(job):
            uses = step.get("uses", "")
            if action_is_unpinned(uses):
                safe_reference = uses if re.fullmatch(r"[A-Za-z0-9_./@-]{1,200}", uses) else "(referensi tidak ditampilkan)"
                ctx.emit("CHA001", f"action {safe_reference} belum dipatok ke SHA commit lengkap.", job=name, step=number)
            scripts = [step.get("run", "")]
            if uses.split("@")[0].lower() == "actions/github-script":
                scripts.append((step.get("with") or {}).get("script", ""))
            if any(untrusted(script) for script in scripts):
                ctx.emit("CHA002", "data PR dipakai langsung dalam run:. Tinjau risiko injeksi perintah shell.", job=name, step=number)


def collect_findings(path, *, ignored=None, advisory_data=None):
    from src.rules import additional, basic, guards, trust

    workflow = load_workflow(path)
    ctx = RuleContext(Path(path), workflow, ignored=set(ignored or ()), advisory_data=advisory_data)
    _base_rules(ctx)
    basic.check(ctx)
    trust.check(ctx)
    guards.check(ctx)
    additional.check(ctx)
    return ctx.findings


def print_text_findings(findings):
    for finding in findings:
        location = "level=workflow"
        if finding["job"] is not None:
            location = f"job={finding['job']}"
            if finding["step"] is not None:
                location += f", langkah={finding['step']}"
        source = finding["file"]
        if isinstance(finding.get("line"), int):
            source += f":{finding['line']}:{finding.get('column', 1)}"
        print(display_text(f"WARNING [{finding['rule_id']}]: {source}: {location}: {finding['message']}"))


def display_text(value):
    """Keep malformed filesystem characters from breaking terminal output."""
    return str(value).encode("utf-8", "backslashreplace").decode("utf-8")


def audit_file(path):
    try:
        findings = collect_findings(path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError):
        print(f"ERROR: Gagal memindai {path}. Periksa format dan akses file.")
        raise SystemExit(2) from None
    print_text_findings(findings)
    return len(findings)

