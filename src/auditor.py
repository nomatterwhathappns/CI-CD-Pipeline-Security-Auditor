"""Command line interface; rule implementations live in src/rules."""

import argparse
import hashlib
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
    analyze_workflow_document,
    load_workflow,
)
from src.registry import RULES, SEVERITIES
from src.policy import (PolicyError, apply_baseline, apply_policy, load_baseline,
                        load_policy, write_baseline)


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


def make_report(target, ignored=None, advisory_file=None, *, config_file=None, baseline_file=None,
                deep=False, repo_root=None, fail_on_unresolved=False):
    from src.rules.guards import load_advisory_data

    ignored = set(ignored or ())
    report = {
        "schema_version": "1.3",
        "auditor_version": __version__,
        "files_scanned": 0,
        "findings_count": 0,
        "findings": [],
        "errors": [],
        "rules_enabled": [rule_id for rule_id in RULES if rule_id not in ignored],
        "rules_ignored": sorted(ignored),
        "advisory_snapshot": None,
        "suppressed_findings": [],
        "suppressed_findings_count": 0,
        "existing_findings_count": 0,
        "new_findings_count": 0,
        "baseline": str(baseline_file) if baseline_file else None,
        "policy": {"file": str(config_file) if config_file else None},
        "analysis": {"mode": "deep" if deep else "workflow", "files_analyzed": [],
                     "unresolved_references": [], "edges": []},
    }
    try:
        policy = load_policy(config_file)
    except PolicyError as error:
        _error(report, config_file, str(error))
        return report
    report["source_root"] = str(policy["root"])
    ignored.update(policy["ignore"])
    report["rules_enabled"] = [rule_id for rule_id in RULES if rule_id not in ignored]
    report["rules_ignored"] = sorted(ignored)
    report["policy"]["suppressions_count"] = len(policy["suppressions"])
    for error in policy["errors"]:
        _error(report, config_file, error)
    known = set()
    if baseline_file:
        try:
            known = load_baseline(baseline_file)
        except PolicyError as error:
            _error(report, baseline_file, str(error))
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

    if deep:
        from src.analysis.graph import analyze_graph

        result = analyze_graph(paths, repo_root or Path.cwd(), ignored=ignored, advisory_data=data)
        report["findings"] = result["findings"]
        report["errors"].extend(result["errors"])
        report["files_scanned"] = len(result["files_analyzed"])
        report["analysis"].update(files_analyzed=result["files_analyzed"],
                                  unresolved_references=result["unresolved"], edges=result["edges"],
                                  limits=result.get("limits", {}),
                                  contexts_analyzed=result.get("contexts_analyzed", 0),
                                  total_source_bytes=result.get("total_source_bytes", 0),
                                  dataflow_limits=result.get("dataflow_limits", {}))
        if result.get("source_digests"):
            from src.policy import relative_file

            root = Path(repo_root or Path.cwd()).resolve()
            identity = sorted((relative_file(path, root), digest)
                              for path, digest in result["source_digests"].items())
            digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("ascii")).hexdigest()
            report["analysis"]["source_digest"] = digest
            for finding in report["findings"]:
                finding["analysis_digest"] = digest
        if fail_on_unresolved and result["unresolved"]:
            _error(report, target, "Ada referensi yang belum dapat dianalisis; lihat analysis.unresolved_references.")
    else:
        for path in paths:
            try:
                findings, flow = analyze_workflow_document(
                    path, load_workflow(path), ignored=ignored, advisory_data=data)
            except (OSError, UnicodeError, ValueError) as error:
                message = str(error) if isinstance(error, AuditError) else "File gagal diperiksa; periksa struktur workflow dan konfigurasi."
                _error(report, path, message)
                continue
            report["files_scanned"] += 1
            report["analysis"]["files_analyzed"].append(str(path))
            report["analysis"]["unresolved_references"].extend(flow.get("unresolved", []))
            report["analysis"]["dataflow_limits"] = flow.get("limits", {})
            report["findings"].extend(findings)
    report["findings_count"] = len(report["findings"])
    apply_policy(report, policy)
    apply_baseline(report, known)
    return report


def print_report(report, output_format):
    if output_format == "sarif":
        from src.reporting import to_sarif

        print(json.dumps(to_sarif(report, report.get("source_root")), indent=2, ensure_ascii=True, allow_nan=False))
        return
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
        if report.get("suppressed_findings_count"):
            print(f"Dikecualikan melalui konfigurasi: {report['suppressed_findings_count']} temuan (lihat laporan JSON/SARIF untuk alasan).")
        if report.get("baseline"):
            print(f"Baseline: {report['existing_findings_count']} temuan lama, {report['new_findings_count']} temuan baru.")
        unresolved = report.get("analysis", {}).get("unresolved_references", [])
        if unresolved:
            print(f"Cakupan: {len(unresolved)} referensi belum dianalisis; lihat laporan JSON/SARIF untuk batasnya.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=f"Audit statis GitHub Actions dengan {len(RULES)} aturan keamanan."
    )
    parser.add_argument("path", nargs="?", default=".github/workflows",
                        help="File/folder workflow (default: .github/workflows)")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text",
                        help="Format laporan (default: text).")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Status 1 jika ada temuan yang mencapai ambang risiko.")
    parser.add_argument("--fail-on-severity", choices=tuple(SEVERITIES), default="low",
                        help="Ambang risiko bersama --fail-on-findings (default: low).")
    parser.add_argument("--ignore", action="append", default=[], metavar="CHAxxx[,CHAyyy]",
                        help="Lewati aturan tertentu; opsi boleh diulang.")
    parser.add_argument("--advisory-file", type=Path,
                        help="Gunakan snapshot advisory JSON lokal yang tervalidasi.")
    parser.add_argument("--config", type=Path,
                        help="Konfigurasi JSON eksplisit untuk aturan dan pengecualian terbatas.")
    parser.add_argument("--baseline", type=Path,
                        help="Kenali temuan lama dari baseline JSON; hanya temuan baru menggagalkan CI.")
    parser.add_argument("--write-baseline", type=Path,
                        help="Simpan baseline setelah pemindaian berhasil; tinjau temuan sebelum menerima baseline.")
    parser.add_argument("--deep", action="store_true",
                        help="Telusuri composite action dan reusable workflow lokal secara terbatas.")
    parser.add_argument("--repo-root", type=Path,
                        help="Batas folder repo untuk --deep (default: folder terminal saat ini).")
    parser.add_argument("--fail-on-unresolved", action="store_true",
                        help="Bersama --deep, status 2 bila ada referensi yang belum dianalisis.")
    parser.add_argument("--list-rules", action="store_true",
                        help="Tampilkan seluruh aturan beserta cakupan dan referensinya.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if not args.deep and (args.repo_root is not None or args.fail_on_unresolved):
        parser.error("--repo-root dan --fail-on-unresolved memerlukan --deep.")
    ignored = _parse_ignored(args.ignore, parser)

    if args.list_rules:
        if args.format == "sarif":
            parser.error("--list-rules memakai --format text atau json.")
        if args.format == "json":
            print(json.dumps({"rules": list(RULES.values())}, indent=2, ensure_ascii=False))
        else:
            for rule in RULES.values():
                print(f"{rule['rule_id']} [{rule['severity']}]: {rule['title']}")
        return 0

    report = make_report(args.path, ignored=ignored, advisory_file=args.advisory_file,
                         config_file=args.config, baseline_file=args.baseline,
                         deep=args.deep, repo_root=args.repo_root, fail_on_unresolved=args.fail_on_unresolved)
    if args.write_baseline:
        try:
            write_baseline(args.write_baseline, report)
        except PolicyError as error:
            _error(report, args.write_baseline, str(error))
    print_report(report, args.format)
    if report["errors"]:
        return 2
    threshold = SEVERITIES[args.fail_on_severity]
    if args.fail_on_findings and any(
        SEVERITIES[finding["severity"]] >= threshold
        and finding.get("baseline_state") != "existing"
        for finding in report["findings"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

