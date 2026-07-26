#!/usr/bin/env python3
"""Reject any change that is not a pure addition to the registry.

Checked per introduced commit, not just between the endpoints: a push that adds
a crate in one commit and removes it in the next has an empty net diff, and an
endpoint-only comparison would wave it through.

Rules, for every commit in (base, head]:

* `crates/**` is add-only. No modify, delete, rename, or mode change.
* Index files may only GROW, and the old bytes must be an exact prefix of the
  new bytes - so a line cannot be reordered, inserted mid-file, or rewritten.
* Every appended index record must be valid JSON, name the crate its path
  implies, carry a version never published before in that file, and point at a
  `.crate` blob that exists in the same tree with a matching checksum.
* Only regular files (mode 100644/100755) may be added anywhere under the
  registry content. Symlinks and gitlinks are refused: a symlink under
  `crates/**` could target mutable content elsewhere in the tree.

Metadata files (`config.json`, the margo UI, this repository's own docs and
workflows) are ordinary files and may change freely.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

METADATA_FILES = {
    "config.json",
    "margo-config.toml",
    "index.html",
    "README.md",
    ".nojekyll",
    ".gitignore",
}
METADATA_PREFIXES = ("assets/", ".github/")
ALLOWED_MODES = {"100644", "100755"}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def is_index_path(path: str) -> bool:
    if path.startswith("crates/"):
        return False
    if path in METADATA_FILES or path.startswith(METADATA_PREFIXES):
        return False
    return True


def blob(rev: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"], capture_output=True
    )
    return result.stdout if result.returncode == 0 else None


class Problems:
    def __init__(self) -> None:
        self.count = 0

    def add(self, path: str, message: str) -> None:
        print(f"::error file={path}::{message}")
        self.count += 1


def check_commit(commit: str, problems: Problems) -> None:
    parent = f"{commit}^"
    changes = git(
        "diff-tree", "-r", "-M", "--no-commit-id", "--root", parent, commit
    ).splitlines()

    for line in changes:
        if not line.startswith(":"):
            continue
        meta, _, paths = line.partition("\t")
        fields = meta[1:].split()
        old_mode, new_mode, _old_sha, _new_sha, status = fields[:5]
        path = paths.split("\t")[0]
        new_path = paths.split("\t")[-1]

        # `.crate` artifacts: additions only.
        if path.startswith("crates/") or new_path.startswith("crates/"):
            if status[0] != "A":
                verb = {"M": "modified", "D": "deleted", "R": "renamed"}.get(
                    status[0], "changed"
                )
                problems.add(
                    path, f"a published .crate was {verb} in {commit[:9]}; "
                    "published versions are immutable"
                )
                continue

        if status[0] in {"A", "M"} and new_mode not in ALLOWED_MODES:
            problems.add(
                new_path,
                f"non-regular file mode {new_mode} in {commit[:9]}; "
                "symlinks and submodules are not allowed in registry content",
            )
            continue

        if not is_index_path(new_path):
            continue

        if status[0] == "D":
            problems.add(
                path, f"an index file was deleted in {commit[:9]}; "
                "published versions are immutable"
            )
            continue
        if status[0] == "R":
            problems.add(
                path, f"an index file was renamed in {commit[:9]}"
            )
            continue

        new_bytes = blob(commit, new_path) or b""
        old_bytes = blob(parent, new_path) if status[0] == "M" else b""
        if old_bytes is None:
            old_bytes = b""

        if not new_bytes.startswith(old_bytes):
            problems.add(
                new_path,
                f"the index file was rewritten in {commit[:9]}; existing bytes "
                "must remain an exact prefix, so records can only be appended",
            )
            continue

        appended = new_bytes[len(old_bytes):]
        existing_versions = {
            json.loads(line)["vers"]
            for line in old_bytes.decode().splitlines()
            if line.strip()
        }
        crate_name = new_path.rsplit("/", 1)[-1]

        for raw in appended.decode().splitlines():
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as error:
                problems.add(new_path, f"appended a malformed index record: {error}")
                continue

            if record.get("name") != crate_name:
                problems.add(
                    new_path,
                    f"record names '{record.get('name')}' but its index path "
                    f"says '{crate_name}'",
                )
            version = record.get("vers")
            if version in existing_versions:
                problems.add(
                    new_path,
                    f"version {version} is already published in this index; "
                    "a published version can never be re-declared",
                )
            existing_versions.add(version)

            prefix = crate_name[:2].lower(), crate_name[2:4].lower()
            crate_path = f"crates/{prefix[0]}/{prefix[1]}/{crate_name}/{version}.crate"
            artifact = blob(commit, crate_path)
            if artifact is None:
                problems.add(
                    new_path,
                    f"index declares {version} but {crate_path} is not in the tree",
                )
                continue
            digest = hashlib.sha256(artifact).hexdigest()
            if record.get("cksum") != digest:
                problems.add(
                    crate_path,
                    "checksum mismatch between the index record and the .crate "
                    f"blob ({record.get('cksum')} vs {digest})",
                )


def main() -> int:
    base, head = sys.argv[1], sys.argv[2]
    commits = git("rev-list", "--reverse", f"{base}..{head}").split()
    if not commits:
        print("no new commits to verify")
        return 0

    problems = Problems()
    for commit in commits:
        check_commit(commit, problems)

    if problems.count:
        print()
        print(
            "Supersede an incorrect train with a new patch train instead. "
            "Nothing already published may be rewritten."
        )
        return 1
    print(f"append-only: {len(commits)} commit(s) verified, nothing rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
