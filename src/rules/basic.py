"""Bounded checks for credential handling, downloads, and container dependencies.

Shell checks inspect literal POSIX commands, never execute them, and skip heredocs
and incomplete quoting. Dynamic image/credential expressions remain unresolved.
"""

from dataclasses import dataclass
import re

from src.rules.common import RuleContext, expressions


_SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY|PRIVATE_KEY|ACCESS_KEY)(?:_|$)",
    re.IGNORECASE,
)
_DESCRIPTIVE_SUFFIX = re.compile(
    r"_(?:NAME|PATH|FILE|URL|TYPE|LENGTH|ENABLED|ROTATION_DAYS)$", re.IGNORECASE
)
_VARIABLE_REFERENCE = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})\Z")
_DIGEST_IMAGE = re.compile(r".+@sha256:[0-9a-fA-F]{64}\Z")
_BULK_SECRETS = re.compile(r"\btoJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)
_GH_AW_SECRET_NAMES = re.compile(r"[A-Z_][A-Z0-9_]*(?:,[A-Z_][A-Z0-9_]*)+\Z")
_GH_AW_METADATA_VALUES = {
    "GH_AW_GITHUB_TOKEN_SOURCE": {"app"},
    "GH_AW_TOKEN_USAGE_SUMMARY_TITLE": {"Threat Detection Token Usage"},
}


def _known_credential_metadata(name, value):
    """Recognize narrowly observed gh-aw labels, never blanket TOKEN suffixes.

    Public cli/cli generated workflows use SECRET_NAMES for a comma-separated
    list of environment identifiers, TOKEN_SOURCE for a provider enum, and
    TOKEN_USAGE_SUMMARY_TITLE for a UI label. Credential-looking replacements
    that do not have these exact values/shapes remain candidates.
    """
    if not isinstance(value, str):
        return False
    if name == "GH_AW_SECRET_NAMES":
        # Require multiple identifiers: a bare token-like literal is not
        # enough evidence that the value is a list of names rather than data.
        return bool(_GH_AW_SECRET_NAMES.fullmatch(value))
    return value in _GH_AW_METADATA_VALUES.get(name, ())


def _literal_credential(value):
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return True
    if not isinstance(value, str) or not value.strip():
        return False
    value = value.strip()
    return "${{" not in value and not _VARIABLE_REFERENCE.fullmatch(value)


def _expression_code(expression):
    """Remove expression string literals before recognizing function calls."""
    return re.sub(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"", "''", expression[3:-2])


def _contains_bulk_secrets(value):
    return any(_BULK_SECRETS.search(_expression_code(part)) for part in expressions(value))


def _containers(job):
    container = job.get("container")
    if isinstance(container, str):
        yield "job", None, {"image": container}
    elif isinstance(container, dict):
        yield "job", None, container
    services = job.get("services", {})
    if isinstance(services, dict):
        for service_name, service in services.items():
            if isinstance(service, dict):
                yield "service", service_name, service


@dataclass
class _Command:
    words: list
    connector: str
    redirected: bool = False


def _commands(script):
    """Recognize simple shell commands while preserving quoted operators.

    Unsupported heredocs and incomplete strings are deliberately left unknown.
    This is a lexical check, not a complete parser or shell data-flow analysis.
    """
    if not isinstance(script, str):
        return []
    tokens, word = [], []
    started, quote, index = False, None, 0

    def flush():
        nonlocal started
        if started:
            tokens.append(("".join(word), False))
            word.clear()
            started = False

    while index < len(script):
        char = script[index]
        if quote:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and index + 1 < len(script):
                following = script[index + 1]
                if following in '$`"\\\n':
                    if following != "\n":
                        word.append(following)
                    index += 1
                else:
                    word.append(char)
            else:
                word.append(char)
        elif char == "\\":
            if index + 1 >= len(script):
                return []
            index += 1
            if script[index] != "\n":
                started = True
                word.append(script[index])
        elif char in "'\"":
            quote, started = char, True
        elif char == "#" and not started:
            while index < len(script) and script[index] != "\n":
                index += 1
            tokens.append(("\n", True))
        elif char in " \t\r":
            flush()
        elif char in "|&;<>();\n":
            flush()
            operator = char
            if index + 1 < len(script) and char + script[index + 1] in {
                "||", "&&", ">>", "<<", "|&", ";;",
            }:
                index += 1
                operator += script[index]
            if operator == "<<":
                return []
            tokens.append((operator, True))
        else:
            started = True
            word.append(char)
        index += 1
    if quote:
        return []
    flush()
    result, words, redirected = [], [], False
    for value, operator in tokens + [("\n", True)]:
        if operator and value in {"|", "|&", "||", "&&", ";", ";;", "&", "(", ")", "\n"}:
            if words:
                result.append(_Command(words, value, redirected))
            words, redirected = [], False
        else:
            if operator and value in {">", ">>", "<"}:
                redirected = True
            words.append(value)
    return result


def _executable(words):
    """Allow explicit command/sudo prefixes and literal environment assignments."""
    words = list(words)
    while words and re.fullmatch(r"[A-Za-z_]\w*=.*", words[0], re.DOTALL):
        words.pop(0)
    if words and words[0] in {"command", "sudo"}:
        words.pop(0)
        if words and words[0] == "--":
            words.pop(0)
    return (words[0].rsplit("/", 1)[-1], words[1:]) if words else ("", [])


def _posix_step(ctx, job, step):
    shell = step.get("shell")
    for scope in (job, ctx.workflow):
        defaults = scope.get("defaults", {})
        run = defaults.get("run", {}) if isinstance(defaults, dict) else {}
        if shell is None and isinstance(run, dict):
            shell = run.get("shell")
    if shell is not None:
        return (isinstance(shell, str) and bool(shell.strip())
                and shell.split()[0].rsplit("/", 1)[-1] in {"bash", "sh"})
    runner = job.get("runs-on", "")
    labels = [runner] if isinstance(runner, str) else runner
    return isinstance(labels, list) and any(
        isinstance(label, str)
        and (label.lower() in {"linux", "macos"} or label.lower().startswith(("ubuntu-", "macos-")))
        for label in labels
    )


def _curl_transfers(arguments):
    """Read common literal curl options; unknown option arguments stay unknown."""
    value_options = {
        "-A", "--user-agent", "-H", "--header", "-d", "--data", "--data-raw",
        "--data-binary", "--data-urlencode", "-u", "--user", "-x", "--proxy",
        "--cacert", "--cert", "--key", "-o", "--output", "--output-dir", "-m",
        "--max-time", "--connect-timeout", "-X", "--request", "-e", "--referer",
        "--resolve", "-w", "--write-out", "--retry", "--url",
    }
    boolean_options = {
        "--fail", "--fail-with-body", "--silent", "--show-error", "--location",
        "--insecure", "--no-insecure", "--compressed", "--globoff", "--head",
        "--remote-name", "--verbose", "--ipv4", "--ipv6", "--http1.1", "--http2",
    }
    transfers, urls = [], []
    insecure, stdout, index, known = False, True, 0, True
    while index < len(arguments):
        token = arguments[index]
        if token == "--next":
            if known:
                transfers.append((urls, insecure, stdout))
            urls, insecure, stdout, known = [], False, True, True
        elif token in value_options:
            if index + 1 >= len(arguments):
                known = False
                break
            index += 1
            value = arguments[index]
            if token == "--url":
                urls.append(value)
            elif token in {"-o", "--output"} and value != "-":
                stdout = False
        elif token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option == "--url":
                urls.append(value)
            elif option == "--output" and value != "-":
                stdout = False
            elif option not in value_options:
                known = False
        elif token in boolean_options:
            if token == "--insecure":
                insecure = True
            elif token == "--no-insecure":
                insecure = False
            elif token in {"--head", "--remote-name"}:
                stdout = False
        elif token.startswith("-"):
            if len(token) > 1 and all(char in "fsSLkIv46gO" for char in token[1:]):
                insecure = insecure or "k" in token[1:]
                stdout = stdout and not any(char in "IO" for char in token[1:])
            elif token.startswith("-o") and len(token) > 2:
                stdout = stdout and token[2:] == "-"
            else:
                known = False
        else:
            urls.append(token)
        index += 1
    if known:
        transfers.append((urls, insecure, stdout))
    return transfers


def _remote_stdout(tool, arguments):
    if tool == "curl":
        return any(stdout and any(re.match(r"https?://", url, re.I) for url in urls)
                   for urls, _, stdout in _curl_transfers(arguments))
    if tool != "wget":
        return False
    to_stdout, urls, index = False, [], 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"-O", "--output-document"} and index + 1 < len(arguments):
            index += 1
            to_stdout = arguments[index] == "-"
        elif token.startswith("--output-document="):
            to_stdout = token.split("=", 1)[1] == "-"
        elif re.fullmatch(r"-[qnv]*O-", token):
            to_stdout = True
        elif re.match(r"https?://", token, re.I):
            urls.append(token)
        elif token not in {"-q", "--quiet", "-nv", "--no-verbose", "--no-check-certificate"}:
            return False
        index += 1
    return to_stdout and bool(urls)


def check(ctx: RuleContext) -> None:
    root_env = ctx.workflow.get("env", {})
    _check_env(ctx, root_env, level="workflow")
    root_fields = {key: value for key, value in ctx.workflow.items() if key != "jobs"}
    if _contains_bulk_secrets(root_fields):
        ctx.emit("CHA006", "The complete secrets context is serialized; pass only required secrets.",
                 level="workflow")

    for job_name, job in ctx.jobs():
        _check_env(ctx, job.get("env", {}), job=job_name, level="job")
        if isinstance(job.get("uses"), str) and job["uses"] and job.get("secrets") == "inherit":
            ctx.emit("CHA005", "Reusable workflow inherits all caller secrets; review and explicitly map required secrets.",
                     job=job_name, confidence="medium")
        job_fields = {key: value for key, value in job.items() if key != "steps"}
        if _contains_bulk_secrets(job_fields):
            ctx.emit("CHA006", "The complete secrets context is serialized; pass only required secrets.", job=job_name)

        for container_type, service_name, container in _containers(job):
            location = {"job": job_name, "container_type": container_type}
            if service_name is not None:
                location["service"] = service_name
            _check_image(ctx, container.get("image"), **location)
            credentials = container.get("credentials", {})
            if isinstance(credentials, dict) and _literal_credential(credentials.get("password")):
                ctx.emit("CHA010", "Registry credentials contain a literal password; use a secret reference.",
                         confidence="medium", **location)

        for step_number, step in ctx.steps(job):
            location = {"job": job_name, "step": step_number}
            _check_env(ctx, step.get("env", {}), level="step", **location)
            if _contains_bulk_secrets(step):
                ctx.emit("CHA006", "The complete secrets context is serialized; pass only required secrets.", **location)
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("docker://"):
                _check_image(ctx, uses[len("docker://"):], **location)
            if not _posix_step(ctx, job, step):
                continue
            commands = _commands(step.get("run"))
            for index, command in enumerate(commands):
                tool, arguments = _executable(command.words)
                if (command.connector == "|" and not command.redirected
                        and index + 1 < len(commands)
                        and _executable(commands[index + 1].words)[0] in {"bash", "sh"}
                        and _remote_stdout(tool, arguments)):
                    ctx.emit("CHA007", "A remote response is piped directly to a shell; verify integrity before execution.", **location)
                    break
            for command in commands:
                tool, arguments = _executable(command.words)
                if tool == "curl" and any(
                    insecure and any(re.match(r"https://", url, re.I) for url in urls)
                    for urls, insecure, _ in _curl_transfers(arguments)
                ):
                    ctx.emit("CHA008", "An HTTPS curl transfer disables TLS certificate verification.", **location)
                    break


def _check_env(ctx, env, **location):
    if not isinstance(env, dict):
        return
    for name, value in env.items():
        if (isinstance(name, str) and _SENSITIVE_NAME.search(name)
                and not _DESCRIPTIVE_SUFFIX.search(name)
                and not _known_credential_metadata(name, value)
                and _literal_credential(value)):
            ctx.emit("CHA004", "A sensitive environment variable contains a literal credential candidate; use a secret reference.",
                     confidence="medium", env_variable=name, **location)


def _check_image(ctx, image, **location):
    if (isinstance(image, str) and image.strip() and "${{" not in image
            and not _VARIABLE_REFERENCE.fullmatch(image.strip())
            and not _DIGEST_IMAGE.fullmatch(image.strip())):
        ctx.emit("CHA009", "A container image is not pinned to a full sha256 digest; tags can change.", **location)
