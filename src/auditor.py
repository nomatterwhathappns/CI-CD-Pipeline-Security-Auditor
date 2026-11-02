"""Command line interface; rule implementations live in src/rules."""

import argparse
import json
from pathlib import Path
import sys

# Preserve both python src/auditor.py and python -m src.auditor entry points.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import __version__
from src.engine import (
    AuditError,
    action_is_unpinned,
    audit_file,
    collect_findings,
    display_text,
    print_text_findings,
)
from src.registry import RULES, SEVERITIES


def _error(report, path, message):
    report["errors"].append({"file": str(path), "message": message})


def _parse_ignored(values, parser):
    ignored = set()
    for value in values:
        for rule_id in value.split(","):
            rule_id = rule_id.strip().upper()
            if rule_id not in RULES:
                parser.error(f"Kode aturan tidak dikenal: {rule_id}")
            ignored.add(rule_id)
    return ignored


def _discover(target):
    if target.is_symlink():
        raise AuditError("Target symlink tidak diperiksa. Pilih file/folder aslinya.")
    if not target.exists():
        raise AuditError("Lokasi tidak ditemukan.")
    if target.is_file():
        if target.suffix.lower() not in {".yml", ".yaml"}:
            raise AuditError("Target file harus memiliki ekstensi .yml atau .yaml.")
        return [target]
    excluded = {".git", ".venv", "__pycache__", "node_modules"}
    paths = sorted(
        path for path in target.rglob("*")
        if not excluded.intersection(path.relative_to(target).parts)
        and not path.is_symlink()
        and path.is_file()
        and path.suffix.lower() in {".yml", ".yaml"}
    )
    if not paths:
        raise AuditError("Tidak ada file workflow YAML ditemukan di target.")
    return paths


def make_report(target, ignored=None, advisory_file=None):
    from src.rules.guards import load_advisory_data

    ignored = set(ignored or ())
    report = {
        "schema_version": "1.1",
        "auditor_version": __version__,
        "files_scanned": 0,
        "findings_count": 0,
        "findings": [],
        "errors": [],
        "rules_enabled": [rule_id for rule_id in RULES if rule_id not in ignored],
        "rules_ignored": sorted(ignored),
        "advisory_snapshot": None,
    }
    try:
        data = load_advisory_data(advisory_file)
    except (OSError, UnicodeError, ValueError):
        _error(report, advisory_file or "bundled-advisories", "Data advisory tidak dapat dibaca atau formatnya tidak valid.")
        return report
    report["advisory_snapshot"] = {
        "checked_at": data["checked_at"],
        "coverage": data["coverage"],
        "entries": len(data["advisories"]),
    }
    try:
        paths = _discover(Path(target))
    except (OSError, ValueError) as error:
        message = str(error) if isinstance(error, AuditError) else "Target tidak dapat diakses."
        _error(report, target, message)
        return report

    for path in paths:
        try:
            findings = collect_findings(path, ignored=ignored, advisory_data=data)
        except (OSError, UnicodeError, ValueError) as error:
            message = str(error) if isinstance(error, AuditError) else "File gagal diperiksa; periksa struktur workflow dan konfigurasi."
            _error(report, path, message)
            continue
        report["files_scanned"] += 1
        report["findings"].extend(findings)
    report["findings_count"] = len(report["findings"])
    return report


def print_report(report, output_format):
    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
        return
    print_text_findings(report["findings"])
    for error in report["errors"]:
        print(display_text(f"ERROR: {error['file']}: {error['message']}"))
    if report["files_scanned"]:
        print(
            f"Selesai: {report['files_scanned']} file dipindai, "
            f"{report['findings_count']} temuan perlu ditinjau."
        )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit statis GitHub Actions dengan aturan CHA001–CHA020."
    )
    parser.add_argument("path", nargs="?", default=".github/workflows",
                        help="File/folder workflow (default: .github/workflows)")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="Format laporan (default: text).")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Status 1 jika ada temuan yang mencapai ambang risiko.")
    parser.add_argument("--fail-on-severity", choices=tuple(SEVERITIES), default="low",
                        help="Ambang risiko bersama --fail-on-findings (default: low).")
    parser.add_argument("--ignore", action="append", default=[], metavar="CHAxxx[,CHAyyy]",
                        help="Lewati aturan tertentu; opsi boleh diulang.")
    parser.add_argument("--advisory-file", type=Path,
                        help="Gunakan snapshot advisory JSON lokal yang tervalidasi.")
    parser.add_argument("--list-rules", action="store_true",
                        help="Tampilkan 20 aturan beserta cakupan dan referensinya.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    ignored = _parse_ignored(args.ignore, parser)

    if args.list_rules:
        if args.format == "json":
            print(json.dumps({"rules": list(RULES.values())}, indent=2, ensure_ascii=False))
        else:
            for rule in RULES.values():
                print(f"{rule['rule_id']} [{rule['severity']}]: {rule['title']}")
        return 0

    report = make_report(args.path, ignored=ignored, advisory_file=args.advisory_file)
    print_report(report, args.format)
    if report["errors"]:
        return 2
    threshold = SEVERITIES[args.fail_on_severity]
    if args.fail_on_findings and any(
        SEVERITIES[finding["severity"]] >= threshold
        for finding in report["findings"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

