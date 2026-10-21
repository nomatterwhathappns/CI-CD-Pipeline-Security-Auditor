import argparse
import re
from pathlib import Path

# Data PR ini ditulis oleh pengaju PR, jadi perlu hati-hati
# jika dimasukkan langsung ke perintah shell.
UNTRUSTED_PR_DATA = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\."
    r"(?:title|body|head\.ref|head\.label)\s*\}\}"
)


def audit_file(path: Path) -> int:
    """Periksa baris run: dan tampilkan temuan yang perlu ditinjau."""
    findings = 0

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        print(f"ERROR: Tidak bisa membaca {path}: {error}")
        return 0

    for line_number, line in enumerate(lines, start=1):
        if "run:" in line and UNTRUSTED_PR_DATA.search(line):
            print(
                f"WARNING: {path}:{line_number}: "
                "data PR dipakai langsung pada baris run:. "
                "Tinjau apakah nilainya dapat ditafsirkan sebagai perintah shell."
            )
            findings += 1

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pindai workflow GitHub Actions untuk pola yang perlu ditinjau."
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
        workflow_files = [target] if target.suffix.lower() in {".yml", ".yaml"} else []
    else:
        workflow_files = sorted(
            path
            for path in target.rglob("*")
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
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
