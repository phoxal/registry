#!/usr/bin/env python3
"""Fixture tests for registry admission outcomes.

Builds tiny synthetic package archives and index/ownership trees in a
temporary directory, then runs the admission validator against them.
Covered outcomes: a valid submission passes, an immutable-version
replacement fails, an inconsistent checksum fails, and an unauthorized
publication fails.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("admission.py")


def build_archive(name: str, version: str, *, lockfile: bool = True) -> bytes:
    root = f"{name}-{version}"
    members = {
        f"{root}/Cargo.toml.orig": (
            f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2024"\n'
        ),
        f"{root}/src/main.rs": "fn main() {}\n",
    }
    if lockfile:
        members[f"{root}/Cargo.lock"] = "version = 4\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member_name, text in sorted(members.items()):
            data = text.encode()
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def index_line(name: str, version: str, blob: bytes, **overrides) -> str:
    entry = {
        "name": name,
        "vers": version,
        "cksum": hashlib.sha256(blob).hexdigest(),
        "deps": [],
        "features": {},
        "yanked": False,
    }
    entry.update(overrides)
    return json.dumps(entry)


def write_tree(
    root: Path,
    *,
    name: str,
    version: str,
    blob: bytes,
    line: str,
) -> None:
    (root / "crates" / name[:2] / name[2:4] / name).mkdir(parents=True, exist_ok=True)
    (root / "crates" / name[:2] / name[2:4] / name / f"{version}.crate").write_bytes(blob)
    index = root / name[:2] / name[2:4] / name
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text(line + "\n")


def write_ownership(root: Path, name: str, owners: list[str]) -> None:
    (root / "ownership").mkdir(parents=True, exist_ok=True)
    (root / "ownership" / f"{name}.json").write_text(
        json.dumps({"kind": "library", "name": name, "owners": owners, "reserved": True})
    )


def git_env(root: Path) -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "HOME": str(root), "PATH": "/usr/bin:/bin",
    }


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True, capture_output=True, env=git_env(root),
    )


def commit_all(root: Path) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-m", "change")


def init_repo_with_pr_branch(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("registry\n")
    git(root, "init", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-m", "base")
    git(root, "checkout", "-b", "pr")


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory()
        self.root = Path(self.workspace.name)
        self.repo = self.root / "repo"
        self.base = self.root / "base"
        self.summary = self.root / "summary.md"
        self.report = self.root / "report.md"
        self.base.mkdir()

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def prepare(self, *, owners: list[str], base_version: str | None = None) -> tuple[str, bytes]:
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(name, version)
        write_tree(
            self.repo, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, owners)
        if base_version is not None:
            old = build_archive(name, base_version)
            write_tree(
                self.base, name=name, version=base_version, blob=old,
                line=index_line(name, base_version, old),
            )
        return name, blob

    def run_admission(self, author: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--repo", str(self.repo),
                "--base-root", str(self.base),
                "--base-ref", "main",
                "--author", author,
                "--summary", str(self.summary),
                "--report", str(self.report),
            ],
            capture_output=True, text=True,
        )

    def test_valid_submission_passes_and_is_eligible(self) -> None:
        name, _ = self.prepare(owners=["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary.read_text()
        self.assertIn(f"`{name} 0.1.0`: integrity verified", summary)
        self.assertIn("NOT IMPLEMENTED / NOT SCANNED", summary)
        self.assertIn("Auto-merge eligibility", summary)
        self.assertIn("First publication", self.report.read_text())

    def test_immutable_version_replacement_fails(self) -> None:
        name = "fixture-pkg"
        version = "0.1.0"
        old = build_archive(name, version)
        write_tree(
            self.base, name=name, version=version, blob=old,
            line=index_line(name, version, old),
        )
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        new = build_archive(name, version, lockfile=False)
        write_tree(
            self.repo, name=name, version=version, blob=new,
            line=index_line(name, version, new),
        )
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("immutable", result.stderr)
        self.assertIn("NOT IMPLEMENTED / NOT SCANNED", self.summary.read_text())

    def test_inconsistent_checksum_fails(self) -> None:
        self.prepare(owners=["alice"])
        name = "fixture-pkg"
        index = self.repo / name[:2] / name[2:4] / name
        broken = json.loads(index.read_text().strip())
        broken["cksum"] = "0" * 64
        index.write_text(json.dumps(broken) + "\n")
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("checksum", result.stderr)

    def test_unauthorized_publication_fails(self) -> None:
        self.prepare(owners=["alice"])
        result = self.run_admission("mallory")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not an enrolled owner", result.stderr)

    def test_control_plane_bundling_is_rejected(self) -> None:
        self.prepare(owners=["alice"])
        workflow = self.repo / ".github" / "workflows" / "evil.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: evil\n")
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("control-plane", result.stderr)


if __name__ == "__main__":
    unittest.main()
