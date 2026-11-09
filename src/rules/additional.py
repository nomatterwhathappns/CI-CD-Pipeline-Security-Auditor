"""Bounded checks for unsafe runner-command opt-ins and container privileges.

These checks inspect declarations only. Expressions that cannot be resolved as
simple literal booleans and unknown Docker option syntax remain unresolved.
"""

import re
import shlex

from src.rules.common import RuleContext


_UNSECURE_COMMANDS = "ACTIONS_ALLOW_UNSECURE_COMMANDS"
_UNKNOWN = object()

# Docker create/run options with separate values. A value such as the label
# "--privileged" is not itself a boolean flag. Unknown syntax is left unresolved.
_DOCKER_VALUE_OPTIONS = {
    "--add-host", "--annotation", "--attach", "--blkio-weight",
    "--blkio-weight-device", "--cap-add", "--cap-drop", "--cgroup-parent",
    "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period",
    "--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
    "--device-write-bps", "--device-write-iops", "--dns", "--dns-option",
    "--dns-search", "--domainname", "--entrypoint", "--env", "--env-file",
    "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval",
    "--health-retries", "--health-start-interval", "--health-start-period",
    "--health-timeout", "--hostname", "--init-path", "--ip", "--ip6", "--ipc",
    "--isolation", "--label", "--label-file", "--link", "--link-local-ip",
    "--log-driver", "--log-opt", "--mac-address", "--memory",
    "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount",
    "--name", "--network", "--network-alias", "--oom-score-adj", "--pid",
    "--pids-limit", "--platform", "--publish", "--pull", "--restart",
    "--runtime", "--security-opt", "--shm-size", "--stop-signal",
    "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs", "--ulimit",
    "--user", "--userns", "--uts", "--volume", "--volume-driver",
    "--volumes-from", "--workdir", "-a", "-c", "-e", "-h", "-l", "-m",
    "-p", "-u", "-v", "-w",
}
_DOCKER_BOOLEAN_OPTIONS = {
    "--detach", "--disable-content-trust", "--init", "--interactive",
    "--no-healthcheck", "--oom-kill-disable", "--publish-all", "--read-only",
    "--rm", "--sig-proxy", "--tty", "-d", "-i", "-P", "-t",
}
_DOCKER_TRUE = {"1", "t", "T", "TRUE", "true", "True"}
_DOCKER_FALSE = {"0", "f", "F", "FALSE", "false", "False"}


def _runner_boolean(value):
    """Match the runner's bool.TryParse opt-in, not generic truthiness."""
    if value is True:
        return True
    if not isinstance(value, str):
        return False
    value = value.strip()
    if "${{" in value:
        match = re.fullmatch(r"\$\{\{\s*(true|false|'(?:[^']|'')*')\s*\}\}", value,
                             re.IGNORECASE)
        if match is None:
            return False
        value = match.group(1)
        if value.startswith("'"):
            value = value[1:-1].replace("''", "'")
    return value.strip().lower() == "true"


def _definitely_disabled(scope):
    condition = scope.get("if")
    if condition is False:
        return True
    if not isinstance(condition, str):
        return False
    # Whitespace outside an expression block can itself create a truthy string.
    # Only recognize one whole false expression or a plain false condition.
    return condition.strip().lower() == "false" or bool(
        re.fullmatch(r"\$\{\{\s*false\s*\}\}", condition, re.IGNORECASE)
    )


def _effective_opt_in(workflow, job, step, job_name, step_number):
    value, origin = _UNKNOWN, None
    for scope, location in (
        (workflow, {"level": "workflow"}),
        (job, {"job": job_name, "level": "job"}),
        (step, {"job": job_name, "step": step_number, "level": "step"}),
    ):
        env = scope.get("env")
        if isinstance(env, str):
            # A complete env expression may replace any inherited variable.
            value, origin = _UNKNOWN, None
        elif isinstance(env, dict) and _UNSECURE_COMMANDS in env:
            value, origin = env[_UNSECURE_COMMANDS], location
    return _runner_boolean(value), origin


def _privileged_option(options):
    """Return True only for a recognized, effective literal privileged flag."""
    if not isinstance(options, str) or "${{" in options:
        return False
    try:
        words = shlex.split(options, posix=True)
    except ValueError:
        return False
    privileged, index = False, 0
    while index < len(words):
        word = words[index]
        option, separator, value = word.partition("=")
        if option == "--privileged":
            if not separator:
                privileged = True
            elif value in _DOCKER_TRUE:
                privileged = True
            elif value in _DOCKER_FALSE:
                privileged = False
            else:
                return False
        elif option in _DOCKER_VALUE_OPTIONS:
            if not separator:
                index += 1
                if index >= len(words):
                    return False
        elif option in _DOCKER_BOOLEAN_OPTIONS:
            if separator and value not in _DOCKER_TRUE | _DOCKER_FALSE:
                return False
        elif word.startswith("-") and not word.startswith("--"):
            # Recognize compact boolean flags and compact value flags.
            if len(word) > 1 and all(char in "diPt" for char in word[1:]):
                pass
            elif word[:2] not in _DOCKER_VALUE_OPTIONS or len(word) <= 2:
                return False
        else:
            # A positional argument or an unknown option could change parsing.
            return False
        index += 1
    return privileged


def check(ctx: RuleContext) -> None:
    reported_origins = set()
    for job_name, job in ctx.jobs():
        if _definitely_disabled(job):
            continue
        for step_number, step in ctx.steps(job):
            if _definitely_disabled(step) or not (step.get("run") or step.get("uses")):
                continue
            enabled, origin = _effective_opt_in(
                ctx.workflow, job, step, job_name, step_number
            )
            if enabled and origin is not None:
                identity = tuple(origin.items())
                if identity not in reported_origins:
                    reported_origins.add(identity)
                    ctx.emit(
                        "CHA021",
                        "Environment mengaktifkan kembali perintah workflow lama "
                        "set-env/add-path. Gunakan GITHUB_ENV/GITHUB_PATH dan "
                        "hapus opt-in yang tidak diperlukan.",
                        **origin,
                    )
        containers = []
        if isinstance(job.get("container"), dict):
            containers.append(("job", None, job["container"]))
        for service_name, service in job.get("services", {}).items():
            if isinstance(service, dict):
                containers.append(("service", service_name, service))
        for container_type, service_name, container in containers:
            if _privileged_option(container.get("options")):
                location = {"job": job_name, "container_type": container_type}
                if service_name is not None:
                    location["service"] = service_name
                ctx.emit(
                    "CHA022",
                    "Container memakai --privileged dan memperoleh hak akses luas. "
                    "Tinjau kebutuhan serta isolasi runner; gunakan kemampuan "
                    "spesifik jika memungkinkan.",
                    **location,
                )
