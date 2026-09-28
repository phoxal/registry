#!/usr/bin/env python3
"""Admission validation for phoxal/registry package submissions.

Validates a pull request that publishes Cargo packages to the static
sparse registry:

- only allowed publication paths change (archives under ``crates/`` and
  index entries under ``ph/``); control-plane changes bundled with
  archives are rejected, and pure control-plane PRs take the human
  review path without auto-merge eligibility;
- archive bytes match the checksum recorded in the submitted index line,
  and the manifest inside the archive agrees with the package identity;
- published versions stay immutable: an existing archive for the same
  version may not be replaced with different bytes, and nothing under
  ``crates/`` may be deleted;
- the submitter is an enrolled owner of the package according to the
  base branch's ``ownership/`` metadata — a PR cannot authorize itself;
- a readable source report is produced against the previously published
  archive (or as a full summary for a first publication).

Package archives are inspected with bounded, path-safe extraction only;
package code is never executed.

Exit codes: 0 admission passed (check outcome success), 1 admission
failed (check outcome failure), 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
from pathlib import Path

# The registry layout limits: prefix directories are the first two and
# next two characters of the lowercased package name.
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
ALLOWED_PREFIXES = ("crates/",)
INDEX_ENTRY = re.compile(r"^[0-9a-z]{2}/[0-9a-z]{2}/[^/]+$")
CONTROL_PLANE_HINTS = (".github/", "ownership/", "config.json", "margo-config.toml", "README.md")
NATIVE_EXTENSIONS = {
    ".a", ".so", ".dylib", ".dll", ".o", ".obj", ".wasm", ".bin", ".exe",
}
SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


class Finding(Exception):
    """One admission rejection reason."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def index_path(name: str) -> Path:
    return Path(name[:2]) / name[2:4] / name


def archive_path(name: str, version: str) -> Path:
    return Path("crates") / name[:2] / name[2:4] / name / f"{version}.crate"


def parse_index_lines(text: str) -> list[dict]:
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise Finding(f"index line {number} is not valid JSON: {error}") from error
    return entries


def read_base_blob(base_root: Path, relative: Path) -> bytes | None:
    path = base_root / relative
    if not path.is_file():
        return None
    return path.read_bytes()


def safe_members(archive: tarfile.TarFile, archive_name: str) -> list[tarfile.TarInfo]:
    """Checks every member for path escapes, links, and size bounds."""
    members = archive.getmembers()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise Finding(
            f"{archive_name}: too many archive members ({len(members)} > {MAX_ARCHIVE_MEMBERS})"
        )
    total = 0
    for member in members:
        total += max(member.size, 0)
        if total > MAX_ARCHIVE_BYTES:
            raise Finding(f"{archive_name}: extracted size exceeds {MAX_ARCHIVE_BYTES} bytes")
        if member.size > MAX_MEMBER_BYTES:
            raise Finding(
                f"{archive_name}: member {member.name} exceeds {MAX_MEMBER_BYTES} bytes"
            )
        raw = member.name
        if raw.startswith("/") or ".." in Path(raw).parts or raw.endswith("/../"):
            raise Finding(f"{archive_name}: member {raw!r} escapes the archive root")
        if member.issym() or member.islnk():
            raise Finding(
                f"{archive_name}: member {raw!r} is a link; links are not published sources"
            )
        if member.isdev():
            raise Finding(f"{archive_name}: member {raw!r} is a device node")
    return members


def extract_manifest(
    blob: bytes, label: str, expected_name: str
) -> tuple[dict[str, str], list[str]]:
    """Reads Cargo.toml.orig (preferred) or Cargo.toml from the archive.

    Returns the ``[package]`` identity fields and the sorted file list.
    """
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
        members = safe_members(archive, label)
        files = sorted(m.name for m in members if m.isfile())
        for candidate in ("Cargo.toml.orig", "Cargo.toml"):
            member = next((m for m in members if m.name.endswith("/" + candidate)), None)
            if member is None:
                continue
            data = archive.extractfile(member).read(MAX_MEMBER_BYTES)
            return (
                parse_manifest_identity(data.decode("utf-8", "replace"), expected_name),
                files,
            )
    raise Finding(f"{label}: archive carries no Cargo manifest")


def parse_manifest_identity(text: str, name: str) -> dict[str, str]:
    package: dict[str, str] = {}
    in_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if not in_package or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        value = value.strip().strip('"')
        if key.strip() in {"name", "version"}:
            package[key.strip()] = value
    if package.get("name") != name:
        raise Finding(
            f"manifest name {package.get('name')!r} does not match the archive identity {name!r}"
        )
    return package


def file_digests(blob: bytes, name: str) -> dict[str, str]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
        members = safe_members(archive, name)
        digests = {}
        for member in members:
            if not member.isfile():
                continue
            data = archive.extractfile(member).read(MAX_MEMBER_BYTES)
            digests[member.name] = sha256_bytes(data)
        return digests


def previous_version(base_root: Path, name: str, version: str) -> tuple[str, bytes] | None:
    """The newest published version below the submitted one, if any."""
    base_index = read_base_blob(base_root, index_path(name))
    if base_index is None:
        return None
    entries = parse_index_lines(base_index.decode("utf-8", "replace"))
    versions = []
    for entry in entries:
        if entry.get("vers") == version or "vers" not in entry:
            continue
        versions.append(entry["vers"])
    versions.sort(key=lambda item: tuple(int(part) for part in item.split("-")[0].split(".")))
    if not versions:
        return None
    older = versions[-1]
    blob = read_base_blob(base_root, archive_path(name, older))
    if blob is None:
        return None
    return older, blob


def diff_report(name: str, version: str, digests: dict[str, str], previous: tuple[str, bytes] | None) -> str:
    lines = [f"### {name} {version}", ""]
    if previous is None:
        lines.append(
            "First publication of this package: full file summary follows "
            "(no previous published archive to diff against)."
        )
    else:
        older, blob = previous
        old = file_digests(blob, f"{name}-{older}")
        prefix = f"{name}-{version}/"
        old_prefix = f"{name}-{older}/"
        new_names = {key.removeprefix(prefix): value for key, value in digests.items()}
        old_names = {key.removeprefix(old_prefix): value for key, value in old.items()}
        added = sorted(set(new_names) - set(old_names))
        removed = sorted(set(old_names) - set(new_names))
        changed = sorted(
            key for key in set(new_names) & set(old_names)
            if new_names[key] != old_names[key]
        )
        lines.append(f"Diff against previous published archive `{older}`:")
        lines.append("")
        lines.append(f"- added: {len(added)}, removed: {len(removed)}, changed: {len(changed)}")
        for key in added:
            lines.append(f"- added `{key}`")
        for key in removed:
            lines.append(f"- removed `{key}`")
        for key in changed:
            lines.append(f"- changed `{key}`")
        lines.append(f"- unchanged: {len(set(new_names) & set(old_names)) - len(changed)}")
    native = sorted(
        key for key in digests
        if Path(key).suffix.lower() in NATIVE_EXTENSIONS or key.endswith("build.rs")
    )
    lines.append("")
    lines.append(
        "Build scripts and native/binary files: "
        + (", ".join(f"`{item}`" for item in native) if native else "none")
    )
    lines.append("")
    return "\n".join(lines)


def changed_paths(repo_root: Path, base_ref: str) -> list[tuple[str, str]]:
    import subprocess

    merge_base = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", base_ref, "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    output = subprocess.run(
        ["git", "-C", str(repo_root), "diff", "--name-status", merge_base, "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout
    changes = []
    for line in output.splitlines():
        if not line.strip():
            continue
        status, _, path = line.partition("\t")
        if status.startswith("R") or status.startswith("C"):
            _, _, path2 = path.partition("\t")
            changes.append((status[0], path2))
            path = path.split("\t")[0]
        changes.append((status[0], path))
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="checkout of the pull request head")
    parser.add_argument("--base-root", required=True, help="checkout of the base branch")
    parser.add_argument("--base-ref", default="origin/main", help="base ref inside --repo")
    parser.add_argument("--author", required=True, help="authenticated pull request author login")
    parser.add_argument("--summary", required=True, help="markdown summary file to append to")
    parser.add_argument("--report", required=True, help="detailed report file to write")
    parser.add_argument(
        "--eligible-out",
        help="file that receives \"true\" when the pull request is auto-merge eligible",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo).resolve()
    base_root = Path(args.base_root).resolve()
    summary_path = Path(args.summary)
    report_path = Path(args.report)
    summary: list[str] = ["## Registry admission", ""]
    report: list[str] = []
    eligible = False

    try:
        changes = changed_paths(repo_root, args.base_ref)
        def is_index_entry(candidate: str) -> bool:
            return INDEX_ENTRY.match(candidate) is not None

        publication = [
            (status, path) for status, path in changes
            if path.startswith(ALLOWED_PREFIXES) or is_index_entry(path)
        ]
        control = [
            (status, path) for status, path in changes
            if not (path.startswith(ALLOWED_PREFIXES) or is_index_entry(path))
        ]
        deleted_publication = [path for status, path in publication if status == "D"]

        if deleted_publication:
            raise Finding(
                "published registry files may not be deleted (append-only history): "
                + ", ".join(deleted_publication)
            )

        if control:
            hints = [path for _, path in control if path.startswith(CONTROL_PLANE_HINTS)]
            if publication:
                raise Finding(
                    "this PR bundles publication changes with control-plane changes "
                    f"({', '.join(path for _, path in control[:5])}); publish them separately"
                )
            summary.append(
                "Control-plane change ("
                + (", ".join(hints[:5]) if hints else "non-registry paths")
                + "): the publication admission did not run. This path requires "
                "human review and is never auto-merge eligible."
            )
            summary.append("")
            eligible = False
            report.append("infrastructure-only pull request; no packages inspected")
        else:
            archives = sorted(
                path for status, path in publication
                if path.startswith("crates/") and path.endswith(".crate")
            )
            index_files = sorted(
                path for status, path in publication if is_index_entry(path)
            )
            for relative in archives:
                parts = Path(relative).parts
                if len(parts) != 5 or parts[4].count(".") < 2:
                    raise Finding(f"unexpected archive path {relative!r}")
                name, file_name = parts[3], parts[4]
                version = file_name[: -len(".crate")]
                if not SEMVER.match(version):
                    raise Finding(f"{relative}: {version!r} is not a valid Cargo version")
                if archive_path(name, version) != Path(relative):
                    raise Finding(
                        f"{relative}: archive path does not match the lowercased "
                        f"package identity {name!r}"
                    )

                blob = (repo_root / relative).read_bytes()
                submitted_sha = sha256_bytes(blob)

                base_archive = read_base_blob(base_root, Path(relative))
                if base_archive is not None:
                    if sha256_bytes(base_archive) != submitted_sha:
                        raise Finding(
                            f"{relative}: version {version} is already published with "
                            "different bytes; published archives are immutable — "
                            "publish a new version instead"
                        )
                    summary.append(
                        f"- `{name} {version}`: identical re-submission of the published "
                        "archive (no-op)."
                    )
                    continue

                index_blob = (repo_root / index_path(name)).read_bytes() \
                    if (repo_root / index_path(name)).is_file() else None
                if index_blob is None:
                    raise Finding(f"{relative}: no index entry submitted for {name}")
                if index_path(name).as_posix() not in index_files:
                    raise Finding(f"{relative}: the index entry for {name} is unchanged")

                entries = parse_index_lines(index_blob.decode("utf-8", "replace"))
                match = next((entry for entry in entries if entry.get("vers") == version), None)
                if match is None:
                    raise Finding(
                        f"{relative}: the submitted index has no line for version {version}"
                    )
                if match.get("name") not in (None, name):
                    raise Finding(f"{relative}: index line names {match.get('name')!r}")
                if match.get("cksum") != submitted_sha:
                    raise Finding(
                        f"{relative}: index checksum {match.get('cksum')!r} does not match "
                        f"the archive bytes ({submitted_sha})"
                    )
                for dependency in match.get("deps", []):
                    if not dependency.get("name") or not dependency.get("req"):
                        raise Finding(
                            f"{relative}: malformed dependency entry in the index line"
                        )

                base_index = read_base_blob(base_root, index_path(name))
                if base_index is not None:
                    base_entries = {
                        entry.get("vers"): entry
                        for entry in parse_index_lines(base_index.decode("utf-8", "replace"))
                    }
                    for entry in entries:
                        old = base_entries.get(entry.get("vers"))
                        if old is None or entry.get("vers") == version:
                            continue
                        if old != entry:
                            yank_only = (
                                old.get("yanked") != entry.get("yanked")
                                and {
                                    key: value for key, value in entry.items()
                                    if key != "yanked"
                                } == {
                                    key: value for key, value in old.items()
                                    if key != "yanked"
                                }
                            )
                            if not yank_only:
                                raise Finding(
                                    f"{index_path(name)}: published index line for "
                                    f"{entry.get('vers')} was modified; only yanking an "
                                    "existing version is allowed"
                                )

                ownership_blob = read_base_blob(base_root, Path("ownership") / f"{name}.json")
                if ownership_blob is None:
                    raise Finding(
                        f"{name}: no ownership record on the base branch; new packages "
                        "require an explicit enrollment decision (a separate, human-reviewed "
                        "ownership change)"
                    )
                ownership = json.loads(ownership_blob)
                owners = ownership.get("owners", [])
                if args.author not in owners:
                    raise Finding(
                        f"{name}: {args.author!r} is not an enrolled owner "
                        f"(owners: {', '.join(owners)})"
                    )

                manifest, files = extract_manifest(blob, f"{name}-{version}", name)
                if manifest.get("version") != version:
                    raise Finding(
                        f"{relative}: manifest version {manifest.get('version')!r} does "
                        f"not match the published version {version!r}"
                    )

                digests = file_digests(blob, f"{name}-{version}")
                summary.append(
                    f"- `{name} {version}`: integrity verified "
                    f"(sha256 `{submitted_sha}`), owner `{args.author}`, "
                    f"{len(files)} files."
                )
                report.append(
                    diff_report(name, version, digests, previous_version(base_root, name, version))
                )
            if not archives:
                summary.append(
                    "No package archives in this pull request; nothing to admit."
                )
            eligible = True
        summary.append("")
        summary.append(
            "Antivirus scan: **NOT IMPLEMENTED / NOT SCANNED** — this admission "
            "establishes publisher authorization and package integrity only; no "
            "antivirus scanning exists."
        )
        summary.append("")
        summary.append(
            "Malware analysis: **NOT IMPLEMENTED / NOT SCANNED** — no static or "
            "dynamic malware analysis runs on submitted archives."
        )
        summary.append("")
    except Finding as finding:
        summary.append(f"**Admission failed:** {finding}")
        summary.append("")
        summary.append(
            "Antivirus scan: **NOT IMPLEMENTED / NOT SCANNED** — this admission "
            "establishes publisher authorization and package integrity only; no "
            "antivirus scanning exists."
        )
        summary.append("")
        summary.append(
            "Malware analysis: **NOT IMPLEMENTED / NOT SCANNED** — no static or "
            "dynamic malware analysis runs on submitted archives."
        )
        summary.append("")
        summary_path.write_text("\n".join(summary), encoding="utf-8")
        report_path.write_text("\n".join(report), encoding="utf-8")
        if args.eligible_out:
            Path(args.eligible_out).write_text("false", encoding="utf-8")
        print(f"admission: {finding}", file=sys.stderr)
        return 1

    summary_path.write_text("\n".join(summary), encoding="utf-8")
    report_path.write_text("\n".join(report), encoding="utf-8")
    if args.eligible_out:
        Path(args.eligible_out).write_text("true" if eligible else "false", encoding="utf-8")
    if eligible:
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(
                "Auto-merge eligibility: this pull request changes only publication "
                "paths, is owner-authorized, and passed integrity validation.\n"
            )
    print(f"admission: passed (auto-merge eligible: {eligible})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
