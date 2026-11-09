"""Explicit, local policy and conservative baselines. Never execute config."""

from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

from src.registry import RULES

MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 10_000


class PolicyError(ValueError):
    """A sanitized policy error suitable for the public report."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("Kunci JSON berulang pada konfigurasi/baseline.")
        result[key] = value
    return result


def _read_json(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_POLICY_BYTES + 1)
        if len(data) > MAX_POLICY_BYTES:
            raise PolicyError("Konfigurasi/baseline melebihi batas 2 MiB.")
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except PolicyError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise PolicyError("Konfigurasi/baseline tidak dapat dibaca atau JSON tidak valid.") from None
    if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1:
        raise PolicyError("Konfigurasi/baseline harus berupa objek dengan version: 1.")
    return result


def _text(value, maximum=500):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return all(char.isprintable() for char in value)


def load_policy(path):
    """Load only when --config is explicit; paths are relative to that file."""
    if path is None:
        return {"root": Path.cwd().resolve(), "ignore": set(), "suppressions": [], "errors": []}
    data = _read_json(path)
    if set(data) - {"version", "ignore", "suppressions"}:
        raise PolicyError("Field konfigurasi tidak dikenal.")
    ignored = data.get("ignore", [])
    entries = data.get("suppressions", [])
    if not isinstance(ignored, list) or any(not isinstance(rule, str) or rule not in RULES for rule in ignored):
        raise PolicyError("ignore harus berupa daftar kode aturan yang dikenal.")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise PolicyError("suppressions harus berupa daftar dengan maksimal 10000 entri.")
    today = datetime.now(timezone.utc).date()
    errors = []
    for index, entry in enumerate(entries, 1):
        required = {"rule_id", "file", "reason", "expires"}
        if not isinstance(entry, dict) or not required <= set(entry) or set(entry) - required - {"job", "step"}:
            raise PolicyError("Setiap pengecualian membutuhkan rule_id, file, reason, expires; job/step opsional.")
        if not isinstance(entry["rule_id"], str) or entry["rule_id"] not in RULES:
            raise PolicyError("Kode aturan pengecualian tidak dikenal.")
        pattern = entry["file"]
        if not _text(pattern, 1000) or "\\" in pattern or ":" in pattern or pattern.startswith("/") or ".." in PurePosixPath(pattern).parts:
            raise PolicyError("file pengecualian harus berupa path/glob relatif POSIX tanpa '..'.")
        if not _text(entry["reason"]):
            raise PolicyError("reason pengecualian harus berupa teks singkat yang tidak kosong.")
        if "job" in entry and (not _text(entry["job"], 100) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", entry["job"])):
            raise PolicyError("job pengecualian harus berupa identifier job yang valid.")
        if "step" in entry and ("job" not in entry or type(entry["step"]) is not int or entry["step"] < 1):
            raise PolicyError("step pengecualian memerlukan job dan nomor langkah positif.")
        try:
            if not isinstance(entry["expires"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["expires"]):
                raise ValueError()
            expired = date.fromisoformat(entry["expires"]) < today
        except ValueError:
            raise PolicyError("expires harus berupa tanggal YYYY-MM-DD yang valid (UTC, inklusif).") from None
        entry["expired"] = expired
        if expired:
            errors.append(f"Pengecualian nomor {index} kedaluwarsa; temuan tetap aktif.")
    return {"root": Path(path).resolve().parent, "ignore": set(ignored), "suppressions": entries, "errors": errors}


def relative_file(path, root):
    """A stable report path; targets outside root keep their absolute identity."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.as_posix()


def fingerprint(finding, root):
    # File content is intentionally part of the baseline identity. An edited
    # workflow requires renewed review, even for the same rule/job/step.
    identity = [finding["rule_id"], relative_file(finding["file"], root),
                finding.get("job"), finding.get("step"), finding["message"],
                finding.get("source_digest"), finding.get("advisory_id"),
                finding.get("severity"), finding.get("confidence")]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def _path_matches(name, pattern):
    """Match POSIX path components; only a whole ** segment crosses '/'.

    Iterative state propagation avoids recursive or exponential globstar
    backtracking. A ** segment matches zero components too, so **/*.yml
    includes both root-level and nested workflow files.
    """
    parts = PurePosixPath(name).parts
    positions = {0}
    for component in PurePosixPath(pattern).parts:
        if component == "**":
            if positions:
                positions = set(range(min(positions), len(parts) + 1))
        else:
            positions = {
                index + 1 for index in positions
                if index < len(parts) and fnmatchcase(parts[index], component)
            }
        if not positions:
            return False
    return len(parts) in positions


def apply_policy(report, policy):
    root = policy["root"]
    active, suppressed = [], []
    for finding in report["findings"]:
        finding["fingerprint"] = fingerprint(finding, root)
        name = relative_file(finding["file"], root)
        matched = None
        if not Path(name).is_absolute():
            for entry in policy["suppressions"]:
                if (not entry["expired"] and entry["rule_id"] == finding["rule_id"]
                        and _path_matches(name, entry["file"])
                        and ("job" not in entry or entry["job"] == finding.get("job"))
                        and ("step" not in entry or entry["step"] == finding.get("step"))):
                    matched = entry
                    break
        if matched:
            finding["suppression"] = {key: matched[key] for key in ("reason", "expires")}
            suppressed.append(finding)
        else:
            active.append(finding)
    report.update(findings=active, findings_count=len(active), suppressed_findings=suppressed,
                  suppressed_findings_count=len(suppressed))


def load_baseline(path):
    data = _read_json(path)
    if set(data) - {"version", "fingerprint_version", "created_at", "auditor_version", "fingerprints"}:
        raise PolicyError("Field baseline tidak dikenal.")
    values = data.get("fingerprints")
    if data.get("fingerprint_version") != "source-sha256-v1" or not isinstance(values, list) or len(values) > MAX_ENTRIES:
        raise PolicyError("Format fingerprint baseline tidak didukung.")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in values):
        raise PolicyError("Fingerprint baseline tidak valid.")
    return set(values)


def apply_baseline(report, known):
    for finding in report["findings"]:
        finding["baseline_state"] = "existing" if finding["fingerprint"] in known else "new"
    report["existing_findings_count"] = sum(f["baseline_state"] == "existing" for f in report["findings"])
    report["new_findings_count"] = report["findings_count"] - report["existing_findings_count"]


def write_baseline(path, report):
    """Atomic write, only after a successful scan; never follows output symlinks."""
    if report["errors"]:
        raise PolicyError("Baseline tidak ditulis karena pemindaian/konfigurasi memiliki kesalahan.")
    path = Path(path)
    if path.suffix.lower() != ".json" or path.is_symlink():
        raise PolicyError("Lokasi baseline harus berupa file .json dan bukan symlink.")
    if path.exists():
        # An explicit refresh may replace a valid baseline, never unrelated JSON.
        load_baseline(path)
    if len(report["findings"]) > MAX_ENTRIES:
        raise PolicyError("Terlalu banyak temuan untuk baseline (maksimal 10000).")
    from src import __version__
    data = {"version": 1, "fingerprint_version": "source-sha256-v1",
            "created_at": datetime.now(timezone.utc).isoformat(), "auditor_version": __version__,
            "fingerprints": sorted({finding["fingerprint"] for finding in report["findings"]})}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, indent=2, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    except (OSError, UnicodeError):
        raise PolicyError("Baseline gagal disimpan; periksa lokasi dan izin tulis.") from None
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass
