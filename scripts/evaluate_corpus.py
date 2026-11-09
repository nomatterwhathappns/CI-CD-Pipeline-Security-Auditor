# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Reproduce the small public-workflow pilot without executing its inputs.

Default operation is offline. --download explicitly retrieves only immutable
GitHub blobs in the manifest, verifies their Git object IDs, and saves data.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from urllib.error import URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import __version__
from src.auditor import make_report

MAX_BYTES = 2 * 1024 * 1024


def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_manifest(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Manifest melebihi 2 MiB.")
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("Manifest tidak valid.")
    entries = data.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 2000:
        raise ValueError("Manifest harus memuat 1–2000 file.")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Entri manifest tidak valid.")
        repo, name, sha = (entry.get(key) for key in ("repo", "path", "sha"))
        if (not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
                or any(part in {".", ".."} for part in repo.split("/"))):
            raise ValueError("Nama repo manifest tidak valid.")
        if (not isinstance(name, str) or not name.startswith(".github/workflows/")
                or not name.endswith((".yml", ".yaml")) or "\\" in name
                or ".." in PurePosixPath(name).parts
                or PurePosixPath(name).as_posix() != name):
            raise ValueError("Lokasi workflow manifest tidak valid.")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Git blob SHA manifest tidak valid.")
        if (repo, name) in seen:
            raise ValueError("File manifest berulang.")
        seen.add((repo, name))
    return data


def evaluate(manifest, corpus_root, *, download=False):
    root = Path(corpus_root).resolve()
    summary = {"auditor_version": __version__, "generated_at": datetime.now(timezone.utc).isoformat(),
               "files_expected": len(manifest["files"]), "files_verified": 0,
               "files_scanned": 0, "findings_count": 0, "rule_counts": {},
               "repositories": {}, "errors": [],
               "interpretation": "Compatibility and pattern-review pilot, not a representative accuracy or exploitability measurement."}
    counts = Counter()
    for entry in manifest["files"]:
        repo, name, sha = entry["repo"], entry["path"], entry["sha"]
        path = root / repo / name
        try:
            # Reject observed symlinks. Corpus directories must remain under
            # the caller's control; concurrent adversarial mutation is outside
            # this standalone evaluation script's filesystem threat model.
            path.resolve().relative_to(root)
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
                raise ValueError("Symlink corpus ditolak.")
            if download:
                url = f"https://api.github.com/repos/{repo}/git/blobs/{sha}"
                request = Request(url, headers={"Accept": "application/vnd.github.raw+json", "User-Agent": "cha-auditor-field-pilot"})
                with urlopen(request, timeout=30) as response:
                    content = response.read(MAX_BYTES + 1)
                if len(content) > MAX_BYTES or git_blob_sha(content) != sha:
                    raise ValueError("Konten unduhan tidak cocok dengan Git blob SHA/batas ukuran.")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.resolve().relative_to(root)
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
                    raise ValueError("Symlink corpus ditolak.")
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
                        temporary = Path(stream.name)
                        stream.write(content)
                    # Atomic replacement avoids following an existing file
                    # symlink/hardlink and never leaves a partially written blob.
                    os.replace(temporary, path)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
            with path.open("rb") as stream:
                content = stream.read(MAX_BYTES + 1)
            if len(content) > MAX_BYTES or git_blob_sha(content) != sha:
                raise ValueError("Isi file tidak cocok dengan Git blob SHA/batas ukuran.")
            summary["files_verified"] += 1
            report = make_report(path)
            item = summary["repositories"].setdefault(repo, {"files_scanned": 0, "findings_count": 0, "rule_counts": {}})
            summary["files_scanned"] += report["files_scanned"]
            summary["findings_count"] += report["findings_count"]
            item["files_scanned"] += report["files_scanned"]
            item["findings_count"] += report["findings_count"]
            local_counts = Counter(finding["rule_id"] for finding in report["findings"])
            counts.update(local_counts)
            for key, number in local_counts.items():
                item["rule_counts"][key] = item["rule_counts"].get(key, 0) + number
            for error in report["errors"]:
                summary["errors"].append({"repo": repo, "path": name, "message": error["message"]})
        except (OSError, ValueError, URLError):
            summary["errors"].append({"repo": repo, "path": name, "message": "File gagal diambil/diverifikasi/dibaca; periksa corpus, jaringan, dan batas API GitHub."})
    summary["rule_counts"] = dict(sorted(counts.items()))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "evaluation/public-corpus.json")
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--download", action="store_true", help="Ambil data blob GitHub; tanpa opsi ini tidak ada akses jaringan.")
    args = parser.parse_args(argv)
    try:
        manifest = read_manifest(args.manifest)
        summary = evaluate(manifest, args.corpus_root, download=args.download)
    except (OSError, UnicodeError, ValueError, RecursionError):
        print(json.dumps({"errors": [{"message": "Manifest tidak dapat dibaca atau formatnya tidak valid."}]}))
        return 2
    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 2 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
