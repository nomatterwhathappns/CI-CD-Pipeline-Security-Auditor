import argparse
import json
import re
from pathlib import Path

import yaml


# Pola data PR yang diperiksa ketika dipakai langsung dalam run.
UNTRUSTED_PR_DATA = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\."
    r"(?:title|body|head\.ref|head\.label)\s*\}\}"
)


def action_is_unpinned(uses: str) -> bool:
    """Kembalikan True jika action belum memakai SHA commit lengkap."""
    if not uses:
        return False

    # Action lokal dan image Docker memerlukan aturan tersendiri.
    if uses.startswith(("./", "docker://")):
        return False

    _, separator, reference = uses.rpartition("@")

    if not separator:
        return True

    return re.fullmatch(r"[0-9a-fA-F]{40}", reference) is None


def collect_findings(path: Path) -> list[dict]:
    """Baca workflow dan kembalikan data temuan."""
    findings = []

    def add_finding(rule_id, message, job=None, step=None):
        findings.append({
            "rule_id": rule_id,
            "file": str(path),
            "job": job,
            "step": step,
            "message": message,
        })

    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    if not isinstance(workflow, dict):
        raise ValueError(
            "Isi workflow harus berupa struktur YAML dengan key."
        )

    # CHA003: periksa izin pada tingkat workflow.
    if workflow.get("permissions") == "write-all":
        add_finding(
            "CHA003",
            "permissions: write-all meminta izin tulis luas. "
            "Tinjau dan batasi sesuai kebutuhan.",
        )

    jobs = workflow.get("jobs", {})

    if not isinstance(jobs, dict):
        raise ValueError("Bagian jobs harus berupa kumpulan job.")

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValueError(
                f"Job {job_name} memiliki format yang salah."
            )

        # CHA003: periksa izin pada tingkat job.
        if job.get("permissions") == "write-all":
            add_finding(
                "CHA003",
                "permissions: write-all meminta izin tulis luas. "
                "Tinjau dan batasi sesuai kebutuhan.",
                job=job_name,
            )

        steps = job.get("steps", [])

        if not isinstance(steps, list):
            raise ValueError(
                f"Bagian steps pada job {job_name} harus berupa daftar."
            )

        for step_number, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                raise ValueError(
                    f"Langkah {step_number} pada job "
                    f"{job_name} tidak valid."
                )

            # CHA001: periksa referensi action.
            uses = step.get("uses", "")

            if not isinstance(uses, str):
                raise ValueError(
                    f"Isi uses pada job {job_name}, "
                    f"langkah {step_number}, harus berupa teks."
                )

            if action_is_unpinned(uses):
                add_finding(
                    "CHA001",
                    f"action {uses} belum dipatok ke SHA commit lengkap.",
                    job=job_name,
                    step=step_number,
                )

            # CHA002: periksa data PR dalam perintah shell.
            command = step.get("run", "")

            if not isinstance(command, str):
                raise ValueError(
                    f"Isi run pada job {job_name}, "
                    f"langkah {step_number}, harus berupa teks."
                )

            if UNTRUSTED_PR_DATA.search(command):
                add_finding(
                    "CHA002",
                    "data PR dipakai langsung dalam run:. "
                    "Tinjau risiko injeksi perintah shell.",
                    job=job_name,
                    step=step_number,
                )

    return findings


def print_text_findings(findings: list[dict]) -> None:
    """Tampilkan data temuan sebagai peringatan teks."""
    for finding in findings:
        location = "level=workflow"

        if finding["job"] is not None:
            location = f"job={finding['job']}"

            if finding["step"] is not None:
                location += f", langkah={finding['step']}"

        print(
            f"WARNING [{finding['rule_id']}]: "
            f"{finding['file']}: {location}: "
            f"{finding['message']}"
        )


def audit_file(path: Path) -> int:
    """Periksa satu file, tampilkan temuan, dan kembalikan jumlahnya."""
    try:
        findings = collect_findings(path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as error:
        print(f"ERROR: Gagal memindai {path}: {error}")
        raise SystemExit(2)

    print_text_findings(findings)
    return len(findings)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pindai workflow GitHub Actions untuk pola yang perlu ditinjau."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".github/workflows",
        help="File atau folder workflow (default: .github/workflows)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Keluar dengan status 1 jika ada temuan.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Format keluaran laporan (default: text).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    workflow_files = []

    report = {
        "files_scanned": 0,
        "findings_count": 0,
        "findings": [],
        "errors": [],
    }

    try:
        if not target.exists():
            raise FileNotFoundError("Lokasi tidak ditemukan.")

        if target.is_file():
            if target.suffix.lower() in {".yml", ".yaml"}:
                workflow_files = [target]
        else:
            workflow_files = sorted(
                path
                for path in target.rglob("*")
                if path.is_file()
                and path.suffix.lower() in {".yml", ".yaml"}
            )

    except (OSError, ValueError) as error:
        report["errors"].append({
            "file": str(target),
            "message": str(error),
        })

    for workflow_file in workflow_files:
        try:
            file_findings = collect_findings(workflow_file)

        except (OSError, UnicodeError, yaml.YAMLError, ValueError) as error:
            report["errors"].append({
                "file": str(workflow_file),
                "message": str(error),
            })
            continue

        report["files_scanned"] += 1
        report["findings"].extend(file_findings)

    report["findings_count"] = len(report["findings"])

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))

    else:
        print_text_findings(report["findings"])

        for error in report["errors"]:
            print(f"ERROR: {error['file']}: {error['message']}")

        if report["files_scanned"] > 0:
            print(
                f"Selesai: {report['files_scanned']} file dipindai, "
                f"{report['findings_count']} temuan perlu ditinjau."
            )
        elif not report["errors"]:
            print(f"Tidak ada file .yml atau .yaml ditemukan di {target}")

    if report["errors"]:
        return 2

    if args.fail_on_findings and report["findings_count"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
