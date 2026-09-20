#!/usr/bin/env python3
"""Focused tests for exact archive review evidence."""

from __future__ import annotations

import json
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import check_admission as admission
import render_review_evidence as evidence
from test_check_admission import make_archive, valid_index, valid_provenance


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_cwd = os.getcwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Registry Test")
        Path("README.md").write_text("base\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.empty = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        os.chdir(self.previous_cwd)
        self.directory.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], check=True, text=True, capture_output=True)

    def publish(self, version: str, marker: bytes) -> str:
        name = "example-service"
        archive = make_archive(version=version, members={"src/value.txt": marker})
        archive_path = admission.canonical_archive_path(name, version)
        Path(archive_path).parent.mkdir(parents=True, exist_ok=True)
        Path(archive_path).write_bytes(archive)
        index_path = admission.canonical_index_path(name)
        Path(index_path).parent.mkdir(parents=True, exist_ok=True)
        records = []
        if Path(index_path).exists():
            records = admission.parse_index_records(Path(index_path).read_bytes(), index_path)
        records.append(valid_index(name, version, archive))
        Path(index_path).write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)
        )
        report = admission.inspect_archive(archive, name, version, "service")
        provenance = Path(admission.provenance_path(name, version))
        provenance.parent.mkdir(parents=True, exist_ok=True)
        provenance.write_bytes(
            valid_provenance(name, version, "service", archive_path, archive, report)
        )
        ownership = Path(admission.ownership_path(name))
        if not ownership.exists():
            ownership.parent.mkdir(parents=True, exist_ok=True)
            ownership.write_text(
                json.dumps({"name": name, "owners": ["alice"], "reserved": True}) + "\n"
            )
        self.git("add", ".")
        self.git("commit", "-qm", f"publish {version}")
        return self.git("rev-parse", "HEAD").stdout.strip()

    def test_first_publication_exposes_the_complete_archive(self) -> None:
        head = self.publish("0.1.0", b"first\n")
        output = Path("evidence")
        written = evidence.render(self.empty, head, output)
        self.assertEqual(len(written), 1)
        package = written[0]
        self.assertEqual((package / "current/src/value.txt").read_bytes(), b"first\n")
        self.assertIn("src/value.txt", (package / "archive.diff").read_text())
        record = json.loads((package / "evidence.json").read_text())
        self.assertIsNone(record["previous_version"])
        self.assertTrue(record["current_inventory"])

    def test_new_version_diffs_against_latest_published_bytes(self) -> None:
        base = self.publish("0.1.0", b"first\n")
        head = self.publish("0.2.0", b"second\n")
        written = evidence.render(base, head, Path("evidence"))
        package = written[0]
        self.assertEqual((package / "previous/src/value.txt").read_bytes(), b"first\n")
        self.assertEqual((package / "current/src/value.txt").read_bytes(), b"second\n")
        diff = (package / "archive.diff").read_text()
        self.assertIn("-first", diff)
        self.assertIn("+second", diff)
        record = json.loads((package / "evidence.json").read_text())
        self.assertEqual(record["previous_version"], "0.1.0")

    def test_new_version_can_diff_against_legacy_archive_metadata(self) -> None:
        base = self.publish("0.1.0", b"first\n")
        archive_path = admission.canonical_archive_path("example-service", "0.1.0")
        archive = Path(archive_path).read_bytes()
        files = admission.extract_archive_files(archive, "example-service", "0.1.0")
        manifest = files["Cargo.toml"] + b'\n[package.metadata.phoxal]\nkind = "service"\n'
        rebuilt = io.BytesIO()
        with tarfile.open(fileobj=rebuilt, mode="w:gz") as output:
            for relative, contents in sorted({**files, "Cargo.toml": manifest}.items()):
                info = tarfile.TarInfo(f"example-service-0.1.0/{relative}")
                info.size = len(contents)
                output.addfile(info, io.BytesIO(contents))
        Path(archive_path).write_bytes(rebuilt.getvalue())
        self.git("add", archive_path)
        self.git("commit", "-qm", "make prior archive legacy")
        base = self.git("rev-parse", "HEAD").stdout.strip()

        head = self.publish("0.2.0", b"second\n")
        written = evidence.render(base, head, Path("evidence"))
        package = written[0]
        self.assertIn("-first", (package / "archive.diff").read_text())


if __name__ == "__main__":
    unittest.main()
