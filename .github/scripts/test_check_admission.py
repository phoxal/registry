#!/usr/bin/env python3
"""Focused unit and integration tests for registry admission."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import check_admission as admission


def make_archive(
    *,
    name: str = "example-service",
    version: str = "0.1.0",
    kind: str = "service",
    include_lib: bool = True,
    include_phoxal_metadata: bool = False,
    members: dict[str, bytes] | None = None,
) -> bytes:
    definition = b"name: example\n"
    manifest_lines = [
        "[package]",
        f'name = "{name}"',
        f'version = "{version}"',
        'edition = "2024"',
        'publish = ["phoxal"]',
        "",
    ]
    if include_phoxal_metadata:
        manifest_lines.extend(
            ["[package.metadata.phoxal]", f'kind = "{kind}"', ""]
        )
    if include_lib:
        manifest_lines.extend(
            [
                "[lib]",
                'path = "src/lib.rs"',
                "",
            ]
        )
    manifest_lines.extend(
        [
            "[[bin]]",
            f'name = "{name}"',
            'path = "src/main.rs"',
            "",
        ]
    )
    package_members = {
        "Cargo.toml": "\n".join(manifest_lines).encode(),
        "service.yaml": definition,
        "src/main.rs": b"fn main() {}\n",
    }
    if include_lib:
        package_members["src/lib.rs"] = b"pub fn run() {}\n"
    if members:
        package_members.update(members)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        root = f"{name}-{version}"
        for path, contents in package_members.items():
            info = tarfile.TarInfo(f"{root}/{path}")
            info.size = len(contents)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(contents))
    return output.getvalue()


def valid_index(name: str, version: str, archive: bytes) -> dict[str, object]:
    return {
        "name": name,
        "vers": version,
        "deps": [],
        "cksum": hashlib.sha256(archive).hexdigest(),
        "features": {},
        "yanked": False,
        "v": 2,
    }


def valid_provenance(
    name: str,
    version: str,
    kind: str,
    archive_path: str,
    archive: bytes,
    report: admission.ArchiveReport,
    publisher: str = "alice",
) -> bytes:
    return json.dumps(
        {
            "name": name,
            "version": version,
            "kind": kind,
            "archive": archive_path,
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "publisher": publisher,
            "source": {
                "origin": "git",
                "revision": "a" * 40,
                "path": "services/example",
                "preparation": "cargo-phoxal/0.1.0",
            },
            "assets": report.inventory,
        },
        sort_keys=True,
    ).encode() + b"\n"


class ArchiveTests(unittest.TestCase):
    def test_valid_service_archive_and_inventory(self) -> None:
        archive = make_archive()
        report = admission.inspect_archive(
            archive, "example-service", "0.1.0", "service"
        )
        self.assertEqual(report.kind, "service")
        self.assertIn("src/lib.rs", report.files)
        self.assertEqual(
            report.inventory[0]["sha256"],
            hashlib.sha256(report.files[report.inventory[0]["path"]]).hexdigest(),
        )

    def test_normalized_internal_dependency_uses_registry_index(self) -> None:
        dependencies = admission._validate_dependencies(
            {
                "dependencies": {
                    "phoxal-build": {
                        "version": "=0.0.0-dev.1",
                        "registry-index": admission.PHOXAL_INDEX,
                    }
                }
            },
            "Cargo.toml",
        )
        self.assertIn("phoxal-build", dependencies)

    def test_normalized_internal_dependency_rejects_crates_io(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "must use"):
            admission._validate_dependencies(
                {
                    "dependencies": {
                        "phoxal-build": {
                            "version": "=0.0.0-dev.1",
                            "registry-index": admission.CRATES_IO_INDEX,
                        }
                    }
                },
                "Cargo.toml",
            )

    def test_archive_identity_must_match_path(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "identity|outside"):
            admission.inspect_archive(
                make_archive(name="other"), "example-service", "0.1.0", "service"
            )

    def test_archive_rejects_symlink(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            info = tarfile.TarInfo("example-service-0.1.0/Cargo.toml")
            contents = b'[package]\nname="example-service"\nversion="0.1.0"\npublish=["phoxal"]\n'
            info.size = len(contents)
            tar.addfile(info, io.BytesIO(contents))
            link = tarfile.TarInfo("example-service-0.1.0/src/main.rs")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        with self.assertRaisesRegex(admission.AdmissionError, "unsafe link"):
            admission.inspect_archive(output.getvalue(), "example-service", "0.1.0")

    def test_archive_rejects_path_escape(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            info = tarfile.TarInfo("example-service-0.1.0/../escape")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(admission.AdmissionError, "outside|unsafe path"):
            admission.inspect_archive(output.getvalue(), "example-service", "0.1.0")

    def test_service_requires_lib_and_bin(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "both lib and bin"):
            admission.inspect_archive(
                make_archive(include_lib=False), "example-service", "0.1.0", "service"
            )

    def test_unknown_kind_is_rejected(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "package kind"):
            admission.inspect_archive(
                make_archive(kind="driver"), "example-service", "0.1.0", "driver"
            )

    def test_new_archive_rejects_custom_phoxal_metadata(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "must not declare"):
            admission.inspect_archive(
                make_archive(include_phoxal_metadata=True),
                "example-service",
                "0.1.0",
                "service",
            )


class RecordTests(unittest.TestCase):
    def test_canonical_short_index_paths(self) -> None:
        self.assertEqual(admission.canonical_index_path("a"), "1/a")
        self.assertEqual(admission.canonical_index_path("ab"), "2/ab")
        self.assertEqual(admission.canonical_index_path("abc"), "3/abc")
        self.assertEqual(admission.canonical_index_path("abcd"), "ab/cd/abcd")

    def test_index_checksum_and_internal_registry(self) -> None:
        archive = make_archive()
        record = valid_index("example-service", "0.1.0", archive)
        record["deps"] = [
            {
                "name": "phoxal-port",
                "req": "^0.1",
                "features": [],
                "optional": False,
                "default_features": True,
                "kind": "normal",
                "registry": None,
            }
        ]
        admission.validate_index_record(record, "ex/am/example-service", archive)

    def test_internal_dependency_cannot_point_at_crates_io(self) -> None:
        archive = make_archive()
        record = valid_index("example-service", "0.1.0", archive)
        record["deps"] = [
            {
                "name": "phoxal",
                "req": "^0.1",
                "features": [],
                "optional": False,
                "default_features": True,
                "kind": "normal",
                "registry": admission.CRATES_IO_INDEX,
            }
        ]
        with self.assertRaisesRegex(admission.AdmissionError, "same-registry"):
            admission.validate_index_record(record, "ex/am/example-service", archive)

    def test_yanked_change_is_narrow(self) -> None:
        archive = make_archive()
        before = json.dumps(valid_index("example-service", "0.1.0", archive), separators=(",", ":")).encode() + b"\n"
        after_record = valid_index("example-service", "0.1.0", archive)
        after_record["yanked"] = True
        after = json.dumps(after_record, separators=(",", ":")).encode() + b"\n"
        self.assertTrue(admission.yanked_only_change(before, after))
        after_record["cksum"] = "0" * 64
        changed = json.dumps(after_record, separators=(",", ":")).encode() + b"\n"
        self.assertFalse(admission.yanked_only_change(before, changed))

    def test_ownership_reserves_name(self) -> None:
        record = admission.validate_ownership(
            b'{"name":"example-service","owners":["alice"],"reserved":true}\n',
            "ownership/example-service.json",
            "example-service",
        )
        self.assertEqual(record["owners"], ["alice"])

    def test_provenance_checks_archive_and_assets(self) -> None:
        archive = make_archive()
        report = admission.inspect_archive(
            archive, "example-service", "0.1.0", "service"
        )
        path = admission.canonical_archive_path("example-service", "0.1.0")
        data = valid_provenance(
            "example-service", "0.1.0", "service", path, archive, report
        )
        owner = {"owners": ["alice"]}
        admission.validate_provenance(
            data,
            "provenance/example-service/0.1.0.json",
            path,
            archive,
            report,
            owner,
        )
        tampered = data.replace(b"services/example", b"../outside")
        with self.assertRaises(admission.AdmissionError):
            admission.validate_provenance(
                tampered,
                "provenance/example-service/0.1.0.json",
                path,
                archive,
                report,
                owner,
            )


class RangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_cwd = os.getcwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Registry Test")
        Path("README.md").write_text("base\n")
        self.git("add", "README.md")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        os.chdir(self.previous_cwd)
        self.directory.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], check=True, text=True, capture_output=True)

    def add_valid_submission(self) -> tuple[str, bytes]:
        archive = make_archive()
        name, version = "example-service", "0.1.0"
        archive_path = admission.canonical_archive_path(name, version)
        Path(archive_path).parent.mkdir(parents=True, exist_ok=True)
        Path(archive_path).write_bytes(archive)
        index_path = admission.canonical_index_path(name)
        Path(index_path).parent.mkdir(parents=True, exist_ok=True)
        Path(index_path).write_text(
            json.dumps(valid_index(name, version, archive), separators=(",", ":")) + "\n"
        )
        report = admission.inspect_archive(archive, name, version, "service")
        prov_path = Path(admission.provenance_path(name, version))
        prov_path.parent.mkdir(parents=True, exist_ok=True)
        prov_path.write_bytes(
            valid_provenance(name, version, "service", archive_path, archive, report)
        )
        own_path = Path(admission.ownership_path(name))
        own_path.parent.mkdir(parents=True, exist_ok=True)
        own_path.write_text(
            json.dumps({"name": name, "owners": ["alice"], "reserved": True}) + "\n"
        )
        self.git("add", ".")
        self.git("commit", "-qm", "submit package")
        return self.git("rev-parse", "HEAD").stdout.strip(), archive

    def test_valid_submission_range(self) -> None:
        head, _archive = self.add_valid_submission()
        self.assertEqual(admission.validate_range(self.base, head), [])

    def test_archive_only_submission_is_rejected(self) -> None:
        archive = make_archive()
        path = admission.canonical_archive_path("example-service", "0.1.0")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(archive)
        self.git("add", ".")
        self.git("commit", "-qm", "archive only")
        head = self.git("rev-parse", "HEAD").stdout.strip()
        problems = admission.validate_range(self.base, head)
        self.assertTrue(any("index" in problem.message for problem in problems))

    def test_yanked_update_does_not_require_new_archive(self) -> None:
        head, _archive = self.add_valid_submission()
        index_path = admission.canonical_index_path("example-service")
        records = admission.parse_index_records(Path(index_path).read_bytes(), index_path)
        records[0]["yanked"] = True
        Path(index_path).write_text(json.dumps(records[0], separators=(",", ":")) + "\n")
        self.git("add", index_path)
        self.git("commit", "-qm", "withdraw package")
        withdrawn = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(admission.validate_range(head, withdrawn), [])

    def test_append_then_yank_are_valid_independent_transitions(self) -> None:
        _first, _archive = self.add_valid_submission()
        name, version = "example-service", "0.2.0"
        archive = make_archive(name=name, version=version)
        archive_path = admission.canonical_archive_path(name, version)
        Path(archive_path).parent.mkdir(parents=True, exist_ok=True)
        Path(archive_path).write_bytes(archive)
        index_path = admission.canonical_index_path(name)
        records = admission.parse_index_records(Path(index_path).read_bytes(), index_path)
        records.append(valid_index(name, version, archive))
        Path(index_path).write_text(
            "\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n"
        )
        report = admission.inspect_archive(archive, name, version, "service")
        provenance = Path(admission.provenance_path(name, version))
        provenance.parent.mkdir(parents=True, exist_ok=True)
        provenance.write_bytes(
            valid_provenance(name, version, "service", archive_path, archive, report)
        )
        self.git("add", ".")
        self.git("commit", "-qm", "append second version")
        self.git("rev-parse", "HEAD")
        records[0]["yanked"] = True
        Path(index_path).write_text(
            "\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n"
        )
        self.git("add", index_path)
        self.git("commit", "-qm", "withdraw first version")
        withdrawn = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(admission.validate_range(self.base, withdrawn), [])


if __name__ == "__main__":
    unittest.main()
