#!/usr/bin/env python3
"""Render review evidence from the exact package archives in a proposed tree.

The admission checker validates safety and consistency first. This command then
extracts the accepted bytes into a bounded artifact and creates a complete Git
binary diff against the most recent published version. First publications diff
against an empty directory, exposing every packaged file for review.
"""

from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import check_admission as admission


class EvidenceError(ValueError):
    """Review evidence cannot be derived from the selected revisions."""


def added_archives(base: str, head: str) -> list[tuple[str, str, str]]:
    """Return canonical archive path, package name, and version additions."""

    result: list[tuple[str, str, str]] = []
    output = subprocess.run(
        ["git", "diff", "--name-status", "--diff-filter=A", base, head, "--", "crates/"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        if status != "A" or not admission.is_archive_path(path):
            continue
        parts = path.split("/")
        if len(parts) != 5 or not parts[-1].endswith(".crate"):
            raise EvidenceError(f"archive path is not canonical: {path}")
        name = parts[-2]
        version = parts[-1][:-6]
        if path != admission.canonical_archive_path(name, version):
            raise EvidenceError(f"archive path is not canonical: {path}")
        result.append((path, name, version))
    return sorted(result)


def previous_archive(base: str, name: str) -> tuple[str, bytes] | None:
    """Return the latest base index version whose immutable archive exists."""

    index_path = admission.canonical_index_path(name)
    index = admission._git_blob(base, index_path)
    if index is None:
        return None
    records = admission.parse_index_records(index, index_path)
    for record in reversed(records):
        if record.get("name") != name or not isinstance(record.get("vers"), str):
            continue
        version = record["vers"]
        path = admission.canonical_archive_path(name, version)
        archive = admission._git_blob(base, path)
        if archive is not None:
            return version, archive
    return None


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    """Materialize already validated regular archive files for review."""

    for relative, contents in sorted(files.items()):
        destination = root.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)


def write_diff(previous: Path, current: Path, destination: Path) -> None:
    """Write a complete textual and binary Git diff without requiring a repo."""

    with destination.open("wb") as output:
        result = subprocess.run(
            [
                "git",
                "diff",
                "--no-index",
                "--binary",
                "--no-renames",
                "--src-prefix=previous/",
                "--dst-prefix=current/",
                str(previous),
                str(current),
            ],
            stdout=output,
            stderr=subprocess.PIPE,
        )
    if result.returncode not in {0, 1}:
        raise EvidenceError(
            "git could not render archive diff: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )


def render(base: str, head: str, output: Path) -> list[Path]:
    """Validate the range and render one evidence directory per new archive."""

    problems = admission.validate_range(base, head)
    if problems:
        detail = "; ".join(f"{problem.path}: {problem.message}" for problem in problems)
        raise EvidenceError(f"registry admission must pass before evidence: {detail}")
    archives = added_archives(base, head)
    if not archives:
        return []
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    written: list[Path] = []
    for archive_path, name, version in archives:
        current_bytes = admission._git_blob(head, archive_path)
        if current_bytes is None:
            raise EvidenceError(f"head tree is missing {archive_path}")
        provenance_path = admission.provenance_path(name, version)
        provenance_bytes = admission._git_blob(head, provenance_path)
        if provenance_bytes is None:
            raise EvidenceError(f"head tree is missing {provenance_path}")
        provenance = admission.parse_provenance(
            provenance_bytes, provenance_path, name, version
        )
        current = admission.inspect_archive(
            current_bytes, name, version, provenance["kind"]
        )
        package = output / f"{name}-{version}"
        current_root = package / "current"
        previous_root = package / "previous"
        current_root.mkdir(parents=True)
        previous_root.mkdir(parents=True)
        write_tree(current_root, current.files)

        prior = previous_archive(base, name)
        previous_version = None
        previous_inventory: list[dict[str, object]] = []
        if prior is not None:
            previous_version, previous_bytes = prior
            previous_files = admission.extract_archive_files(
                previous_bytes, name, previous_version
            )
            write_tree(previous_root, previous_files)
            previous_inventory = admission.archive_inventory(previous_files)
        write_diff(previous_root, current_root, package / "archive.diff")
        evidence = {
            "name": name,
            "version": version,
            "previous_version": previous_version,
            "archive_path": archive_path,
            "archive_sha256": hashlib.sha256(current_bytes).hexdigest(),
            "current_inventory": current.inventory,
            "previous_inventory": previous_inventory,
        }
        (package / "evidence.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(package)
    return written


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 3:
        print("usage: render_review_evidence.py BASE HEAD OUTPUT", file=sys.stderr)
        return 2
    try:
        written = render(args[0], args[1], Path(args[2]))
    except (EvidenceError, admission.AdmissionError, subprocess.CalledProcessError, OSError) as error:
        print(f"::error::review evidence failed: {error}", file=sys.stderr)
        return 1
    print(f"registry review evidence: {len(written)} package(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
