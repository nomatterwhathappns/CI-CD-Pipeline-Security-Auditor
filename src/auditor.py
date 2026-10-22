import argparse
import re
from pathlib import Path

import yaml


# Pola data PR yang kita periksa ketika dipakai langsung dalam run.
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


def audit_file(path: Path) -> int:
    """Periksa action dan seluruh isi run pada setiap langkah workflow."""
    findings = 0

    try:
        text = path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(text)

        if not isinstance(workflow, dict):
            raise ValueError(
                "Isi workflow harus berupa struktur YAML dengan key."
            )

        jobs = workflow.get("jobs", {})

        if not isinstance(jobs, dict):
            raise ValueError("Bagian jobs harus berupa kumpulan job.")

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                raise ValueError(
                    f"Job {job_name} memiliki format yang salah."
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

                # Aturan pertama: periksa referensi action.
                uses = step.get("uses", "")

                if not isinstance(uses, str):
                    raise ValueError(
                        f"Isi uses pada job {job_name}, "
                        f"langkah {step_number}, harus berupa teks."
                    )

                if action_is_unpinned(uses):
                    print(
                        f"WARNING [GHA001]: {path}: job={job_name}, "
                        f"langkah={step_number}: "
                        f"action {uses} belum dipatok ke SHA commit lengkap."
                    )
                    findings += 1

                # Aturan kedua: periksa data PR di dalam perintah shell.
                command = step.get("run", "")

                if not isinstance(command, str):
                    raise ValueError(
                        f"Isi run pada job {job_name}, "
                        f"langkah {step_number}, harus berupa teks."
                    )

                if UNTRUSTED_PR_DATA.search(command):
                    print(
                        f"WARNING [GHA002]: {path}: job={job_name}, "
                        f"langkah={step_number}: "
                        "data PR dipakai langsung dalam run:. "
                        "Tinjau risiko injeksi perintah shell."
                    )
                    findings += 1

    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as error:
        print(f"ERROR: Gagal memindai {path}: {error}")
        raise SystemExit(2)

    return findings


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
    args = parser.parse_args()

    target = Path(args.path)

    if not target.exists():
        print(f"ERROR: Lokasi tidak ditemukan: {target}")
        return 2

    if target.is_file():
        workflow_files = (
            [target]
            if target.suffix.lower() in {".yml", ".yaml"}
            else []
        )
    else:
        workflow_files = sorted(
            path
            for path in target.rglob("*")
            if path.is_file()
            and path.suffix.lower() in {".yml", ".yaml"}
        )

    if not workflow_files:
        print(f"Tidak ada file .yml atau .yaml ditemukan di {target}")
        return 0

    total_findings = 0

    for workflow_file in workflow_files:
        total_findings += audit_file(workflow_file)

    print(
        f"Selesai: {len(workflow_files)} file dipindai, "
        f"{total_findings} temuan perlu ditinjau."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
