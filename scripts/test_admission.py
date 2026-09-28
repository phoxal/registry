#!/usr/bin/env python3
"""Fixture tests for registry admission outcomes.

Builds synthetic package archives and index/ownership trees in a
temporary directory, then runs the admission validator against them.
Covered outcomes: a valid submission passes (including TOML that naive
string splitting mishandles and dependency records that must agree),
an immutable-version replacement fails, an inconsistent checksum
fails, an unauthorized publication fails, control-plane bundling is
rejected, index-only tampering (checksum change, removed version,
unauthorized yank) fails, an authorized yank passes, duplicate index
records fail, and a new index line without an archive fails. A
structural test pins the trusted-workflow contract: the workflow must
execute the base branch's validator through a base-context trigger and
bind the merge to the checked head.
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
WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "admission.yml"


def build_archive(
    name: str,
    version: str,
    *,
    lockfile: bool = True,
    manifest_name: str | None = None,
    manifest_version: str | None = None,
    manifest_extra: str = "",
    duplicate_manifest: bool = False,
) -> bytes:
    """A Cargo-shaped archive: normalized Cargo.toml plus Cargo.toml.orig."""
    root = f"{name}-{version}"
    normalized = (
        f"[package]\nname = \"{manifest_name or name}\"\n"
        f"version = \"{manifest_version or version}\"\nedition = \"2024\"\n"
        f"{manifest_extra}\n"
    )
    members = {
        f"{root}/Cargo.toml": normalized,
        f"{root}/Cargo.toml.orig": normalized,
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
        if duplicate_manifest:
            data = normalized.encode()
            info = tarfile.TarInfo(f"{root}/Cargo.toml")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def index_line(
    name: str,
    version: str,
    blob: bytes,
    *,
    deps: list[dict] | None = None,
    yanked: bool = False,
    **overrides,
) -> str:
    entry = {
        "name": name,
        "vers": version,
        "cksum": hashlib.sha256(blob).hexdigest(),
        "deps": deps or [],
        "features": {},
        "yanked": yanked,
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


def write_index(root: Path, name: str, lines: list[str]) -> None:
    index = root / name[:2] / name[2:4] / name
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text("".join(line + "\n" for line in lines))


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

    def prepare(self, *, owners: list[str]) -> str:
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(name, version)
        write_tree(
            self.repo, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, owners)
        return name

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
        name = self.prepare(owners=["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.summary.read_text()
        self.assertIn(f"`{name} 0.1.0`: integrity verified", summary)
        self.assertIn("NOT IMPLEMENTED / NOT SCANNED", summary)
        self.assertIn("Auto-merge eligibility", summary)
        self.assertIn("First publication", self.report.read_text())
        self.assertIn("`fixture-pkg-0.1.0/src/main.rs`", self.report.read_text())

    def test_manifest_toml_that_string_splitting_mishandles_still_passes(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(
            name, version,
            manifest_extra='description = "version = 9.9.9 # name = fake-package"',
        )
        write_tree(
            self.repo, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, ["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_and_index_dependencies_must_agree(self) -> None:
        name = "fixture-pkg"
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(
            name, "0.1.0",
            manifest_extra=(
                '[dependencies]\nanyhow = "=1.0.1"\n'
            ),
        )
        matching = index_line(name, "0.1.0", blob, deps=[
            {"name": "anyhow", "req": "=1.0.1", "kind": "normal", "registry": None},
        ])
        write_tree(self.repo, name=name, version="0.1.0", blob=blob, line=matching)
        commit_all(self.repo)
        self.assertEqual(self.run_admission("alice").returncode, 0)

        second = self.root / "repo2"
        init_repo_with_pr_branch(second)
        blob2 = build_archive(name, "0.2.0")
        unpaired = index_line(name, "0.2.0", blob2, deps=[
            {"name": "anyhow", "req": "=1.0.1", "kind": "normal", "registry": None},
        ])
        write_tree(second, name=name, version="0.2.0", blob=blob2, line=unpaired)
        commit_all(second)
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--repo", str(second),
                "--base-root", str(self.base),
                "--base-ref", "main",
                "--author", "alice",
                "--summary", str(self.summary),
                "--report", str(self.report),
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not declare", result.stderr)

    def test_immutable_version_replacement_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
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
        # Rewriting a published record — including its checksum — is an
        # immutability violation detected through the index comparison.
        self.assertIn("record was modified", result.stderr)
        self.assertIn("only yanking", result.stderr)
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

    def test_index_only_checksum_tamper_requires_ownership_and_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        blob = build_archive(name, version)
        write_tree(
            self.base, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        tampered = json.loads(index_line(name, version, blob))
        tampered["cksum"] = "0" * 64
        write_index(self.repo, name, [json.dumps(tampered)])
        commit_all(self.repo)
        result = self.run_admission("mallory")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not an enrolled owner", result.stderr)
        # Even the enrolled owner cannot rewrite published checksums.
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("only yanking", result.stderr)

    def test_removed_version_line_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        old = build_archive(name, "0.0.9")
        current = build_archive(name, version)
        write_tree(
            self.base, name=name, version="0.0.9", blob=old,
            line=index_line(name, "0.0.9", old),
        )
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        write_tree(
            self.repo, name=name, version=version, blob=current,
            line=index_line(name, version, current),
        )
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("was removed", result.stderr)

    def test_authorized_yank_passes_and_unauthorized_yank_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        blob = build_archive(name, version)
        write_tree(
            self.base, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        yanked = json.loads(index_line(name, version, blob))
        yanked["yanked"] = True
        write_index(self.repo, name, [json.dumps(yanked)])
        commit_all(self.repo)
        self.assertEqual(self.run_admission("mallory").returncode, 1)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("index-only change", self.summary.read_text())

    def test_duplicate_index_records_fail(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        blob = build_archive(name, version)
        write_tree(
            self.base, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        newer = build_archive(name, "0.2.0")
        write_tree(
            self.repo, name=name, version="0.2.0", blob=newer,
            line=index_line(name, "0.2.0", newer),
        )
        index = self.repo / name[:2] / name[2:4] / name
        index.write_text(index.read_text() + index_line(name, "0.2.0", newer) + "\n")
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate", result.stderr)

    def test_new_index_line_without_archive_fails(self) -> None:
        name = "fixture-pkg"
        write_ownership(self.base, name, ["alice"])
        init_repo_with_pr_branch(self.repo)
        phantom = build_archive(name, "0.9.0")
        write_index(self.repo, name, [index_line(name, "0.9.0", phantom)])
        commit_all(self.repo)
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no submitted archive", result.stderr)

    def test_conflicting_normalized_manifest_fails(self) -> None:
        # The normalized Cargo.toml Cargo consumes disagrees with the
        # published identity; Cargo.toml.orig still matches it.
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(
            name, version, manifest_name="different-package", manifest_version="9.9.9"
        )
        write_tree(
            self.repo, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, ["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match the published identity", result.stderr)

    def test_missing_normalized_manifest_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(name, version)
        # Strip the normalized manifest, keeping only Cargo.toml.orig.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(blob)) as source, \
                tarfile.open(fileobj=buffer, mode="w:gz") as target:
            for member in source.getmembers():
                if member.name.endswith("/Cargo.toml"):
                    continue
                target.addfile(member, source.extractfile(member))
        stripped = buffer.getvalue()
        write_tree(
            self.repo, name=name, version=version, blob=stripped,
            line=index_line(name, version, stripped),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, ["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("exactly one normalized manifest", result.stderr)

    def test_duplicate_authoritative_manifest_member_fails(self) -> None:
        name, version = "fixture-pkg", "0.1.0"
        init_repo_with_pr_branch(self.repo)
        blob = build_archive(name, version, duplicate_manifest=True)
        write_tree(
            self.repo, name=name, version=version, blob=blob,
            line=index_line(name, version, blob),
        )
        commit_all(self.repo)
        write_ownership(self.base, name, ["alice"])
        result = self.run_admission("alice")
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate", result.stderr)


class WorkflowContractTests(unittest.TestCase):
    def test_the_workflow_runs_base_policy_in_a_base_context(self) -> None:
        text = WORKFLOW.read_text()
        self.assertIn("pull_request_target", text, "must use the base-context trigger")
        self.assertNotIn("python3 pr/scripts/admission.py", text)
        self.assertIn("base/scripts/admission.py", text)
        self.assertIn("--match-head-commit", text)


if __name__ == "__main__":
    unittest.main()
