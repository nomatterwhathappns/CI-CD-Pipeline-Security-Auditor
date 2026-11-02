"""Bounded checks for trust crossings; scripts and artifacts are never executed.

These checks follow known action inputs and a small set of shell patterns. They
do not resolve action SHAs, repository settings, arbitrary shell programs, or
the contents of artifacts. Unknown cases are not proof of safety.
"""

import fnmatch
import posixpath
import re

from .common import expressions, untrusted


_CHECKOUT_V7 = {"3d3c42e5aac5ba805825da76410c181273ba90b1"}
_UPLOAD_HIDDEN_DEFAULT = {"1746f4ab65b179e0ea60a494b83293b640dd5bba"}
_UPLOAD_HIDDEN_OFF = {"cf430e030ddbb5b0abf93d22962f4752f3646cd9"}
_PR_CHECKOUT = re.compile(
    r"github\.(?:head_ref|event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)"
    r"|merge_commit_sha|number))\b", re.I,
)
_RUN_CHECKOUT = re.compile(r"github\.event\.workflow_run\.(?:head_sha|head_branch|head_repository\.full_name)\b", re.I)
_VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)(?::[^}]*)?\}|([A-Za-z_]\w*))")
_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$")
_LOW_TRUST = {"pull_request_target", "workflow_run", "issue_comment"}
_SENSITIVE_SAMPLES = (
    ".env", ".env.production", ".git/config", ".npmrc", ".pypirc", ".netrc",
    ".aws/credentials", ".ssh/id_rsa", ".ssh/id_ed25519", "id_rsa", "id_ed25519",
)


def _action(step):
    value = step.get("uses", "")
    if not isinstance(value, str):
        return "", ""
    name, _, ref = value.rpartition("@")
    return name.lower(), ref.lower()


def _inputs(step):
    value = step.get("with", {})
    return value if isinstance(value, dict) else {}


def _version_parts(ref):
    """Recognize bounded version tags; arbitrary refs remain unresolved."""
    match = re.fullmatch(r"v([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:\.([0-9]{1,3}))?(?:-[0-9A-Za-z.-]+)?", ref)
    return tuple(int(part) if part is not None else None for part in match.groups()) if match else None


def _true(value):
    if value is True:
        return True
    if not isinstance(value, str):
        return False
    return value.strip().removeprefix("${{").removesuffix("}}").strip().lower() == "true"


def _condition(scope):
    value = scope.get("if", "")
    if value is False:
        return "false"
    if isinstance(value, str) and "${{" in value:
        parts = list(expressions(value))
        if len(parts) == 1 and parts[0] == value:
            return value[3:-2].strip()
        # Outside whitespace is literal text to the runner, not part of the
        # expression. Composite/malformed values cannot prove a job is disabled.
        return "__unknown_condition__"
    return str(value).strip()


def _active(job, step=None, event=None):
    for scope in (job, step or {}):
        condition = _condition(scope)
        if condition.lower() in {"false", "0"}:
            return False
        match = re.fullmatch(r"github\.event_name\s*==\s*['\"]([^'\"]+)['\"]", condition)
        if match and event and match[1] != event:
            return False
        match = re.fullmatch(r"github\.event_name\s*!=\s*['\"]([^'\"]+)['\"]", condition)
        if match and event and match[1] == event:
            return False
    return True


def _path(value):
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    for workspace in ("${{ github.workspace }}", "$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}"):
        if text == workspace or text.startswith(workspace + "/"):
            text = "." + text[len(workspace):]
    for temporary in ("${{ runner.temp }}", "$RUNNER_TEMP", "${RUNNER_TEMP}"):
        if text == temporary or text.startswith(temporary + "/"):
            text = "/__runner_temp__" + text[len(temporary):]
    if "${{" in text or "$" in text:
        return None
    return posixpath.normpath(text or ".")


def _inside(path, root):
    if path is None or root is None:
        return False
    path, root = posixpath.normpath(path), posixpath.normpath(root)
    if root == ".":
        return not path.startswith(("/", "../", "~/")) and path != ".."
    return path == root or path.startswith(root.rstrip("/") + "/")


def _checkout_root(step):
    return _path(_inputs(step).get("path", "."))


def _checkout_cleans(step, root):
    clean = _inputs(step).get("clean", True)
    return (
        _action(step)[0] == "actions/checkout"
        and clean is not False and str(clean).lower() != "false"
        and _inside(root, _checkout_root(step))
    )


def _untrusted_checkout(step, event):
    name, ref = _action(step)
    if name != "actions/checkout":
        return False
    options = _inputs(step)
    values = [options.get("ref", ""), options.get("repository", "")]
    matcher = _RUN_CHECKOUT if event == "workflow_run" else _PR_CHECKOUT
    suspicious = any(matcher.search(part) for value in values for part in expressions(value))
    suspicious |= bool(re.search(r"(?:^|/)refs/pull/\d+/(?:head|merge)$", str(options.get("ref", ""))))
    if not suspicious:
        return False
    version = _version_parts(ref)
    protected = ref in _CHECKOUT_V7 or version is not None and version[0] >= 7
    # v7 blocks fork PR refs by default. Unknown SHAs remain review findings.
    if protected:
        opt_in = options.get("allow-unsafe-pr-checkout", False)
        if opt_in is False or opt_in is None or isinstance(opt_in, str) and opt_in.strip().lower() in {"", "false", "${{ false }}"}:
            return False
    return True


def _working_directory(ctx, job, step):
    value = "."
    for scope in (ctx.workflow, job):
        defaults = scope.get("defaults", {})
        run = defaults.get("run", {}) if isinstance(defaults, dict) else {}
        if isinstance(run, dict):
            value = run.get("working-directory", value)
    return _path(step.get("working-directory", value))


def _commands(script):
    # Reuse the lexical parser's operator provenance: a quoted '|' or ';' is
    # an argument, while an actual operator separates executable commands.
    from .basic import _commands as parse_commands

    yield from (command.words for command in parse_commands(script))


def _executes(ctx, job, step, root):
    """Recognize code execution inside a known checkout/artifact directory."""
    local = step.get("uses", "")
    if isinstance(local, str) and local.startswith("./"):
        return _inside(_path(local), root)
    script = step.get("run", "")
    if not isinstance(script, str) or root is None:
        return False
    cwd = _working_directory(ctx, job, step)
    if cwd is None:
        return False
    for words in _commands(script):
        words = list(words)
        while words and re.match(r"[A-Za-z_]\w*=", words[0]):
            words.pop(0)
        if not words:
            continue
        command = posixpath.basename(words[0]).lower()
        args = words[1:]
        if command == "cd" and args:
            path = _path(args[0])
            cwd = posixpath.normpath(posixpath.join(cwd, path)) if path is not None else None
            if cwd is None:
                return False
            continue
        if words[0].startswith(("./", "../", "/")) and _inside(posixpath.normpath(posixpath.join(cwd, words[0])), root):
            return True
        if command in {"bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "pwsh", "powershell", "source", "."}:
            if any(x in {"-c", "-command", "-encodedcommand"} for x in args):
                continue
            if "-m" in args and command.startswith("python") and _inside(cwd, root):
                return True
            files = [x for x in args if not x.startswith("-") and x not in {">", ">>"}]
            if files and _inside(posixpath.normpath(posixpath.join(cwd, files[0])), root):
                return True
        if not _inside(cwd, root):
            continue
        if command in {"npm", "pnpm", "yarn", "bun"} and args and args[0] in {"ci", "install", "run", "run-script", "test", "build", "publish", "exec", "x"}:
            return True
        if command in {"make", "cmake", "gradle", "gradlew", "mvn", "pytest", "tox", "nox", "bundle", "rake"} and not any(x in {"--version", "--help", "-h"} for x in args):
            return True
        if command in {"cargo", "go", "dotnet"} and args and args[0] in {"build", "test", "run", "install", "publish", "restore"}:
            return True
    return False


def _execution_after(ctx, job, start, root, event, stop=None):
    for number, step in ctx.steps(job):
        if number <= start or stop is not None and number >= stop or not _active(job, step, event):
            continue
        if _checkout_cleans(step, root):
            # A later checkout replaces this source; do not attribute execution to it.
            return None
        if _executes(ctx, job, step, root):
            return number
    return None


def _download(step):
    name, _ = _action(step)
    options = _inputs(step)
    if name == "actions/download-artifact":
        run = options.get("run-id", "")
        if not any("github.event.workflow_run.id" in x for x in expressions(run)):
            return None
    elif name == "dawidd6/action-download-artifact":
        # On workflow_run this action can fetch artifacts from a preceding run.
        # An explicit unrelated numeric run is outside this bounded check.
        run = options.get("run_id", "")
        if run and not any("github.event.workflow_run.id" in x for x in expressions(run)):
            return None
    else:
        return None
    return _path(options.get("path", "."))


def _glob_matches(path, pattern):
    pattern = pattern.removeprefix("./").rstrip("/")
    patterns = {pattern}
    if pattern.startswith("**/"):
        patterns.add(pattern[3:])
    return any(fnmatch.fnmatchcase(path, item) or path.startswith(item + "/") for item in patterns)


def _hidden_uploaded(step):
    options = _inputs(step)
    name, ref = _action(step)
    if name != "actions/upload-artifact":
        return False
    version = _version_parts(ref)
    if ref in _UPLOAD_HIDDEN_DEFAULT or version is not None and (version[0] < 4 or version[0] == 4 and version[1] is not None and version[1] < 4):
        return True  # Older versions do not implement the exclusion-by-default input.
    if "include-hidden-files" in options:
        return _true(options["include-hidden-files"])
    if ref in _UPLOAD_HIDDEN_OFF or version is not None and version[0] >= 4:
        return False
    return None  # An arbitrary full SHA cannot be version-resolved offline.


def _sensitive_path(path):
    pieces = path.lower().split("/")
    basename = pieces[-1]
    if basename.endswith((".example", ".sample", ".template", ".pub")):
        return False
    return (
        basename in {".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519"}
        or basename.startswith(".env.")
        or path.lower().endswith((".aws/credentials", ".git/config"))
        or basename in {".git", ".ssh", ".aws"}
    )


def _artifact_sensitive(step):
    if _action(step)[0] != "actions/upload-artifact":
        return False
    options = _inputs(step)
    paths = options.get("path", "")
    if not isinstance(paths, str):
        return False
    lines = [line.strip() for line in paths.splitlines() if line.strip()]
    excluded = [_path(line[1:]) for line in lines if line.startswith("!")]
    excluded = [line for line in excluded if line is not None]
    hidden = _hidden_uploaded(step)
    for line in lines:
        if line.startswith("!"):
            continue
        path = _path(line)
        if path is None:
            continue
        candidates = []
        if _sensitive_path(path):
            candidates = [path]
        elif path in {".", "*", "**", "**/*", "~"} and hidden is True:
            candidates = list(_SENSITIVE_SAMPLES)
        elif any(x in path for x in "*?["):
            candidates = [sample for sample in _SENSITIVE_SAMPLES if _glob_matches(sample, path)]
        for candidate in candidates:
            if any(piece.startswith(".") and piece not in {".", ".."} for piece in candidate.split("/")) and hidden is not True:
                continue
            if not any(_glob_matches(candidate, pattern) for pattern in excluded):
                return True
    return False


def _cache_paths(step):
    paths = _inputs(step).get("path", "")
    return [_path(line.strip()) for line in paths.splitlines() if line.strip() and not line.strip().startswith("!")] if isinstance(paths, str) else []


def _without_comment(text):
    quote = None
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
        elif character == "\\" and quote != "'":
            escaped = True
        elif character == quote:
            quote = None
        elif quote is None and character in "'\"":
            quote = character
        elif quote is None and character == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    return text


def _variables(text):
    # Shell single-quoted literals do not expand $VARIABLE. GitHub expressions,
    # by contrast, are expanded before shell quoting and are checked separately.
    text = re.sub(r"'[^']*'", "", text)
    return {match[1] or match[2] for match in _VAR.finditer(text)}


def _file_source(text, roots):
    for words in _commands(text):
        if words and words[0] in {"cat", "source", "."}:
            if any(_inside(_path(word), root) for word in words[1:] for root in roots):
                return True
    # Command substitution has '(' attached or separated by the shell lexer.
    for match in re.finditer(r"\bcat\s+['\"]?([^\s'\";)]+)", text):
        if any(_inside(_path(match[1]), root) for root in roots):
            return True
    return False


def _line_sanitized(text):
    # Only recognize an explicit CR+LF removal or one-line encoding. Merely
    # quoting a variable does not make environment-file writes safe.
    text = text.strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    if not text.startswith("$(") or not text.endswith(")"):
        return False
    inner = text[2:-1]
    if any(separator in inner for separator in (";", "&&", "||", "\n")):
        return False
    return bool(re.search(
        r"\|\s*(?:tr\s+-d\s+['\"](?:\\r\\n|\\n\\r)['\"]|base64\s+(?:-w\s*0|--wrap(?:=|\s+)0))\s*$", inner,
    ))


def _validation(text):
    """Recognize small, explicit single-line/allowlist guards."""
    variable = r"['\"]?\$\{?([A-Za-z_]\w*)\}?['\"]?"
    guard = re.fullmatch(r"(?:if\s+)?\[\[\s*(.*?)\s*\]\]\s*(?:;\s*then|then|\|\|\s*(?:exit|return)(?:\s+\d+)?\s*;?)", text)
    if not guard:
        return None, None
    numeric = re.fullmatch(variable + r"\s*=~\s*\^\[0-9\]\+\$", guard[1])
    allow = re.fullmatch(variable + r"\s*==\s*['\"](/[-A-Za-z0-9_./]+)['\"]", guard[1])
    return (numeric[1] if numeric else None, allow[1] if allow else None)


def _random_delimiter_safe(text, random_variables):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 5 or lines[0] != "{" or not lines[-1].startswith("}"):
        return False
    if not all(re.match(r"(?:echo|printf|cat)\s", line) and not re.search(r">\s*['\"]?\$", line) for line in lines[2:-2]):
        return False
    return any(
        re.fullmatch(r'(?:echo|printf)\s+"[A-Za-z_]\w*<<\$\{?' + re.escape(name) + r'\}?"', lines[1])
        and re.fullmatch(r'(?:echo|printf)\s+"\$\{?' + re.escape(name) + r'\}?"', lines[-2])
        for name in random_variables
    )


def _environment_writes(ctx, job, step, artifact_roots):
    script = step.get("run", "")
    if not isinstance(script, str):
        return set()
    tainted = {name for name, value in ctx.env_for(job, step).items() if isinstance(name, str) and untrusted(value)}
    line_safe, path_safe, random_variables = set(), set(), set()
    findings, guards, group = set(), [], []

    def snapshot():
        return (tainted.copy(), line_safe.copy(), path_safe.copy(), random_variables.copy())

    def merge(branches):
        all_tainted = set().union(*(branch[0] for branch in branches))
        # A value must be safe on every path where it remains tainted. A literal
        # reassignment on another path is safe without requiring a guard there.
        safe_line = {name for name in all_tainted if all(name not in branch[0] or name in branch[1] for branch in branches)}
        safe_path = {name for name in all_tainted if all(name not in branch[0] or name in branch[2] for branch in branches)}
        random = set.intersection(*(branch[3] for branch in branches))
        return all_tainted, safe_line, safe_path, random

    def inspect(text):
        source_vars = _variables(text) & tainted
        raw_source = untrusted(text) or _file_source(text, artifact_roots)
        for target in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
            if not re.search(r">{1,2}\s*['\"]?\$(?:\{" + target + r"\}|" + target + r"(?!\w))", text):
                continue
            safe_vars = path_safe if target == "GITHUB_PATH" else line_safe
            if not raw_source and not source_vars - safe_vars:
                continue
            filtered_pipeline = (
                "\n" not in text and not any(x in text for x in (";", "&&", "||"))
                and re.search(r"\|\s*(?:tr\s+-d\s+['\"](?:\\r\\n|\\n\\r)['\"]|base64\s+-w\s*0)\s*>>?", text)
            )
            if target != "GITHUB_PATH" and (filtered_pipeline or _random_delimiter_safe(text, random_variables)):
                continue
            findings.add("CHA017" if target == "GITHUB_PATH" else "CHA016")

    for raw_line in script.splitlines():
        line = _without_comment(raw_line).strip()
        if not line:
            continue
        branch = re.match(r"(if|elif|else|fi)(?:\s|;|$)", line)
        keyword = branch[1] if branch else None
        if keyword == "if":
            guards.append({"base": snapshot(), "branches": [], "else": False})
        elif keyword in {"elif", "else"} and guards:
            frame = guards[-1]
            frame["branches"].append(snapshot())
            tainted, line_safe, path_safe, random_variables = (part.copy() for part in frame["base"])
            frame["else"] = keyword == "else"
        elif keyword == "fi" and guards:
            frame = guards.pop()
            frame["branches"].append(snapshot())
            if not frame["else"]:
                frame["branches"].append(frame["base"])
            tainted, line_safe, path_safe, random_variables = merge(frame["branches"])
        validation_line = "if" + line[4:] if keyword == "elif" else line
        numeric, allowed = _validation(validation_line)
        if keyword in {"if", "elif"} and (numeric or allowed):
            if numeric:
                line_safe.add(numeric)
            if allowed:
                line_safe.add(allowed)
                path_safe.add(allowed)
        elif re.search(r"\|\|\s*(?:exit|return)\b", line):
            if numeric:
                line_safe.add(numeric)
            if allowed:
                line_safe.add(allowed)
                path_safe.add(allowed)
        assignment = _ASSIGN.match(line)
        if assignment:
            name, value = assignment.groups()
            source = untrusted(value) or bool(_variables(value) & tainted) or _file_source(value, artifact_roots)
            tainted.discard(name)
            line_safe.discard(name)
            path_safe.discard(name)
            random_variables.discard(name)
            if source:
                tainted.add(name)
                references = _variables(value) & tainted
                if _line_sanitized(value) or references and references <= line_safe and not untrusted(value) and not _file_source(value, artifact_roots):
                    line_safe.add(name)
                if references and references <= path_safe and not untrusted(value) and not _file_source(value, artifact_roots):
                    path_safe.add(name)
            if not source and re.fullmatch(r"\$\(\s*(?:uuidgen|openssl\s+rand\s+-hex\s+\d+)\s*\)", value):
                random_variables.add(name)
        if group or line.startswith("{") and not line.startswith("${{"):
            group.append(line)
            if re.search(r"\}\s*>>?", line):
                inspect("\n".join(group))
                group = []
        else:
            inspect(line)
    return findings


def check(ctx):
    """Emit CHA011–CHA017 for recognized risky combinations."""
    events = ctx.event_names
    for job_name, job in ctx.jobs():
        if not _active(job):
            continue
        labels = job.get("runs-on", [])
        if isinstance(labels, dict):
            labels = labels.get("labels", [])
        if isinstance(labels, str):
            labels = [labels]
        if not isinstance(labels, list):
            labels = []
        pr_events = events & {"pull_request", "pull_request_target"}
        if any(isinstance(label, str) and label.lower() == "self-hosted" for label in labels) and any(_active(job, event=event) for event in pr_events):
            ctx.emit("CHA011", "Job PR dapat memakai runner self-hosted; tinjau persetujuan dan isolasi runner.", job=job_name, confidence="medium")

        artifact_roots = []
        downloads = []
        unsafe_executions = []
        for number, step in ctx.steps(job):
            if not _active(job, step):
                continue
            if _action(step)[0] == "actions/checkout":
                artifact_roots = [root for root in artifact_roots if not _checkout_cleans(step, root)]
                downloads = [(source, root) for source, root in downloads if not _checkout_cleans(step, root)]
            for event in events & (_LOW_TRUST | {"pull_request"}):
                if not _active(job, step, event) or not _untrusted_checkout(step, event):
                    continue
                execution = _execution_after(ctx, job, number, _checkout_root(step), event)
                if execution is not None:
                    unsafe_executions.append(execution)
                    if event == "pull_request_target":
                        ctx.emit("CHA012", "Kode head/fork PR di-checkout lalu dijalankan dalam konteks pull_request_target.", job=job_name, step=number, confidence="medium")
                        break
            if "workflow_run" in events and _active(job, step, "workflow_run"):
                root = _download(step)
                if root is not None:
                    artifact_roots.append(root)
                    downloads.append((number, root))
                    execution = _execution_after(ctx, job, number, root, "workflow_run")
                    if execution is not None:
                        unsafe_executions.append(execution)
                        ctx.emit("CHA013", "Artifact dari run pemicu dapat memengaruhi berkas yang kemudian dijalankan.", job=job_name, step=number, confidence="medium")
            if _artifact_sensitive(step):
                ctx.emit("CHA014", "Pola upload artifact dapat menyertakan berkas kredensial; batasi path dan pengecualiannya.", job=job_name, step=number, confidence="medium")
            for rule_id in sorted(_environment_writes(ctx, job, step, artifact_roots)):
                ctx.emit(rule_id, "Data tak tepercaya ditulis ke file environment/output tanpa pembatasan yang dikenali." if rule_id == "CHA016" else "Data tak tepercaya dapat menambahkan direktori pencarian perintah melalui GITHUB_PATH.", job=job_name, step=number, confidence="medium")

        cache_mode = job.get("cache-mode", ctx.workflow.get("cache-mode"))
        if not isinstance(cache_mode, str) or cache_mode not in {"write", "write-only"} or not events & _LOW_TRUST:
            continue
        for number, step in ctx.steps(job):
            name, _ = _action(step)
            if name not in {"actions/cache", "actions/cache/save"} or not _active(job, step):
                continue
            paths = _cache_paths(step)
            if not paths or not any(_active(job, step, event) for event in events & _LOW_TRUST):
                continue
            limit = number if name.endswith("/save") else len(job.get("steps", [])) + 1
            execution = any(item < limit for item in unsafe_executions)
            injected_files = any(source < limit and any(_inside(root, path) or _inside(path, root) for path in paths) for source, root in downloads)
            direct_injection = any(
                index < limit and _active(job, item) and untrusted(item.get("run", ""))
                for index, item in ctx.steps(job)
            )
            if execution or injected_files or direct_injection:
                ctx.emit("CHA015", "Cache scope istimewa diberi izin tulis saat kode/data tak tepercaya dapat memengaruhi isinya.", job=job_name, step=number, confidence="medium")
