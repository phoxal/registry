#!/usr/bin/env python3
"""Admission validation for phoxal/registry package submissions.

Validates a pull request that publishes Cargo packages to the static
sparse registry. Validation is driven by every changed package
identity — a changed archive, a changed index entry, or both:

- only allowed publication paths change (archives under ``crates/`` and
  index entries under the two-character prefix directories); control-
  plane changes bundled with archives are rejected, and pure
  control-plane PRs take the human review path without auto-merge
  eligibility;
- the submitted index is compared completely against the trusted base
  index for every affected package: no published version line may be
  removed or modified except an authorized yank toggle, duplicate
  version records are rejected, and every new version line must pair
  with a new archive whose bytes hash to the recorded checksum;
- the manifest Cargo actually consumes — the normalized root
  ``Cargo.toml`` inside the archive — is parsed with a real TOML parser
  and must agree with the archive identity and the index dependency
  records; the informational ``Cargo.toml.orig`` is never trusted;
- published versions stay immutable: an existing archive for the same
  version may not be replaced with different bytes, and nothing under
  ``crates/`` may be deleted;
- the submitter is an enrolled owner of every affected package
  according to the base branch's ``ownership/`` metadata — index-only
  operations such as yanks require the same authority;
- a readable source report is produced: unified diffs of bounded text
  files against the previously published archive, or a full file
  listing for a first publication.

Package archives are inspected with bounded, path-safe extraction only;
package code is never executed.

Exit codes: 0 admission passed, 1 admission failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python before 3.11: the maintained backport.
    import tomli as tomllib

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_DIFF_BYTES = 256 * 1024
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


def version_key(version: str) -> tuple:
    """A deliberate ordering key: numeric core, then the raw remainder."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", version)
    if match is None:
        return (0, 0, 0, version)
    core = tuple(int(part) for part in match.group(1, 2, 3))
    return (*core, match.group(4))


def parse_index(text: str, label: str) -> dict[str, dict]:
    """Parses index lines into a version table, rejecting duplicates."""
    entries: dict[str, dict] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise Finding(f"{label} line {number} is not valid JSON: {error}") from error
        version = entry.get("vers")
        if not isinstance(version, str) or not version:
            raise Finding(f"{label} line {number} has no version")
        if version in entries:
            raise Finding(f"{label}: duplicate index record for version {version}")
        entries[version] = entry
    return entries


def read_base_blob(base_root: Path, relative: Path) -> bytes | None:
    path = base_root / relative
    if not path.is_file():
        return None
    return path.read_bytes()


def safe_members(archive: tarfile.TarFile, archive_name: str) -> list[tarfile.TarInfo]:
    """Checks every member for duplicates, path escapes, links, size bounds."""
    members = archive.getmembers()
    seen: set[str] = set()
    for member in members:
        if member.name in seen:
            raise Finding(
                f"{archive_name}: duplicate archive member {member.name!r}"
            )
        seen.add(member.name)
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
        if raw.startswith("/") or ".." in Path(raw).parts:
            raise Finding(f"{archive_name}: member {raw!r} escapes the archive root")
        if member.issym() or member.islnk():
            raise Finding(
                f"{archive_name}: member {raw!r} is a link; links are not published sources"
            )
        if member.isdev():
            raise Finding(f"{archive_name}: member {raw!r} is a device node")
    return members


def read_archive(blob: bytes, label: str) -> tuple[list[tarfile.TarInfo], tarfile.TarFile]:
    archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    return safe_members(archive, label), archive


def extract_manifest(
    blob: bytes, label: str, expected_name: str, expected_version: str
) -> tuple[dict, dict[str, list[dict]]]:
    """Parses the normalized root ``Cargo.toml`` Cargo consumes.

    The informational ``Cargo.toml.orig`` is never a substitute. The
    authoritative manifest must appear exactly once at the archive root.
    """
    members, archive = read_archive(blob, label)
    root = f"{expected_name}-{expected_version}/Cargo.toml"
    manifest_members = [m for m in members if m.name == root]
    if len(manifest_members) != 1:
        raise Finding(
            f"{label}: the archive must carry exactly one normalized manifest "
            f"at `{root}` (found {len(manifest_members)})"
        )
    data = archive.extractfile(manifest_members[0]).read(MAX_MEMBER_BYTES)
    try:
        manifest = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise Finding(f"{label}: the normalized manifest is not valid TOML: {error}") from error
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise Finding(f"{label}: the normalized manifest has no [package] table")
    if package.get("name") != expected_name:
        raise Finding(
            f"{label}: manifest name {package.get('name')!r} does not match the "
            f"published identity {expected_name!r}"
        )
    dependencies: dict[str, list[dict]] = {}
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(section, {})
        if not isinstance(table, dict):
            raise Finding(f"{label}: [{section}] is not a table")
        for dep_name, spec in table.items():
            requirement = spec if isinstance(spec, str) else spec.get("version")
            dependencies.setdefault(section, []).append(
                {"name": dep_name, "req": requirement if isinstance(requirement, str) else None}
            )
    return package, dependencies


def file_digests(blob: bytes, name: str) -> dict[str, str]:
    members, archive = read_archive(blob, name)
    digests = {}
    for member in members:
        if not member.isfile():
            continue
        data = archive.extractfile(member).read(MAX_MEMBER_BYTES)
        digests[member.name] = sha256_bytes(data)
    return digests


def file_contents(blob: bytes, name: str) -> dict[str, bytes]:
    members, archive = read_archive(blob, name)
    contents = {}
    for member in members:
        if not member.isfile() or member.size > MAX_DIFF_BYTES:
            continue
        contents[member.name] = archive.extractfile(member).read(MAX_MEMBER_BYTES)
    return contents


def previous_version(base_root: Path, name: str, version: str) -> tuple[str, bytes] | None:
    """The greatest published version strictly below the submitted one."""
    base_index = read_base_blob(base_root, index_path(name))
    if base_index is None:
        return None
    entries = parse_index(base_index.decode("utf-8", "replace"), f"base index for {name}")
    versions = [
        entry for entry in entries
        if version_key(entry) < version_key(version)
    ]
    if not versions:
        return None
    older = max(versions, key=version_key)
    blob = read_base_blob(base_root, archive_path(name, older))
    if blob is None:
        return None
    return older, blob


def diff_report(
    name: str, version: str, blob: bytes, previous: tuple[str, bytes] | None
) -> str:
    lines = [f"### {name} {version}", ""]
    digests = file_digests(blob, f"{name}-{version}")
    native = sorted(
        key for key in digests
        if Path(key).suffix.lower() in NATIVE_EXTENSIONS or key.endswith("build.rs")
    )
    if previous is None:
        lines.append(
            f"First publication of `{name}`; the complete file summary follows "
            f"({len(digests)} files)."
        )
        lines.append("")
        for member in sorted(digests):
            lines.append(f"- `{member}` sha256 `{digests[member]}`")
    else:
        older, old_blob = previous
        old_digests = file_digests(old_blob, f"{name}-{older}")
        prefix = f"{name}-{version}/"
        old_prefix = f"{name}-{older}/"
        new_names = {key.removeprefix(prefix): value for key, value in digests.items()}
        old_names = {key.removeprefix(old_prefix): value for key, value in old_digests.items()}
        added = sorted(set(new_names) - set(old_names))
        removed = sorted(set(old_names) - set(new_names))
        changed = sorted(
            key for key in set(new_names) & set(old_names)
            if new_names[key] != old_names[key]
        )
        lines.append(
            f"Diff against previous published archive `{older}`: "
            f"{len(added)} added, {len(removed)} removed, {len(changed)} changed, "
            f"{len(set(new_names) & set(old_names)) - len(changed)} unchanged."
        )
        lines.append("")
        for key in added:
            lines.append(f"- added `{key}`")
        for key in removed:
            lines.append(f"- removed `{key}`")
        old_contents = file_contents(old_blob, f"{name}-{older}")
        new_contents = file_contents(blob, f"{name}-{version}")
        for key in changed:
            lines.append(f"- changed `{key}`")
            old_text = old_contents.get(old_prefix + key)
            new_text = new_contents.get(prefix + key)
            if old_text is None or new_text is None:
                lines.append(f"  - binary or larger than {MAX_DIFF_BYTES} bytes; no text diff")
                continue
            try:
                delta = "\n".join(difflib.unified_diff(
                    old_text.decode("utf-8").splitlines(),
                    new_text.decode("utf-8").splitlines(),
                    fromfile=f"{older}:{key}",
                    tofile=f"{version}:{key}",
                    lineterm="",
                ))
            except UnicodeDecodeError:
                lines.append("  - not decodable text; no text diff")
                continue
            for diff_line in delta.splitlines():
                lines.append(f"  {diff_line}")
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


def compare_dependencies(
    name: str, version: str, index_deps: list[dict], manifest_deps: dict[str, list[dict]]
) -> None:
    """The index dependency records must agree with the manifest."""
    section_by_kind = {
        "normal": "dependencies",
        "dev": "dev-dependencies",
        "build": "build-dependencies",
    }
    index_records = {
        (section_by_kind.get(dep.get("kind"), "dependencies"), dep["name"]): dep["req"]
        for dep in index_deps
    }
    for section, dependencies in manifest_deps.items():
        for dep in dependencies:
            key = (section, dep["name"])
            if key in index_records:
                recorded = index_records.pop(key)
                if dep["req"] is not None and dep["req"] != recorded:
                    raise Finding(
                        f"{name} {version}: manifest requires {dep['name']} "
                        f"{dep['req']!r} but the index records {recorded!r}"
                    )
    for (section, dep_name) in index_records:
        raise Finding(
            f"{name} {version}: the index records a {section} entry for "
            f"{dep_name!r} that the normalized manifest does not declare"
        )


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
        help='file that receives "true" when the pull request is auto-merge eligible',
    )
    args = parser.parse_args()

    repo_root = Path(args.repo).resolve()
    base_root = Path(args.base_root).resolve()
    summary_path = Path(args.summary)
    report_path = Path(args.report)
    eligible = False
    summary: list[str] = []
    report: list[str] = []

    def finish(finding: Finding | None) -> int:
        body = ["## Registry admission", ""] + summary
        if finding is not None:
            body.append(f"**Admission failed:** {finding}")
        body += [
            "",
            "Antivirus scan: **NOT IMPLEMENTED / NOT SCANNED** — this admission "
            "establishes publisher authorization and package integrity only; no "
            "antivirus scanning exists.",
            "",
            "Malware analysis: **NOT IMPLEMENTED / NOT SCANNED** — no static or "
            "dynamic malware analysis runs on submitted archives.",
            "",
        ]
        summary_path.write_text("\n".join(body), encoding="utf-8")
        report_path.write_text("\n".join(report), encoding="utf-8")
        if args.eligible_out:
            Path(args.eligible_out).write_text(
                "true" if eligible and finding is None else "false", encoding="utf-8"
            )
        return 1 if finding is not None else 0

    try:
        changes = changed_paths(repo_root, args.base_ref)
        publication = [
            (status, path) for status, path in changes
            if path.startswith(ALLOWED_PREFIXES) or INDEX_ENTRY.match(path)
        ]
        control = [
            (status, path) for status, path in changes
            if not (path.startswith(ALLOWED_PREFIXES) or INDEX_ENTRY.match(path))
        ]
        deleted_publication = [path for status, path in publication if status == "D"]
        if deleted_publication:
            raise Finding(
                "published registry files may not be deleted (append-only history): "
                + ", ".join(deleted_publication)
            )
        if control:
            if publication:
                raise Finding(
                    "this PR bundles publication changes with control-plane changes "
                    f"({', '.join(path for _, path in control[:5])}); publish them separately"
                )
            summary.append(
                "Control-plane change ("
                + (", ".join(
                    path for _, path in control if path.startswith(CONTROL_PLANE_HINTS)
                )[:400] or "non-registry paths")
                + "): the publication admission did not run. This path requires "
                "human review and is never auto-merge eligible."
            )
            return finish(None)

        changed_archives = {
            path for status, path in publication
            if path.startswith("crates/") and path.endswith(".crate")
        }
        changed_indexes = sorted(
            path for status, path in publication if INDEX_ENTRY.match(path)
        )
        # Affected packages: any changed archive or index entry drives
        # complete validation, so index-only operations cannot bypass it.
        affected: set[str] = set()
        for relative in changed_archives:
            parts = Path(relative).parts
            if len(parts) != 5 or parts[4].count(".") < 2:
                raise Finding(f"unexpected archive path {relative!r}")
            affected.add(parts[3])
        for entry in changed_indexes:
            affected.add(Path(entry).parts[2])
        if not affected:
            summary.append("No publication changes in this pull request.")
            return finish(None)

        for name in sorted(affected):
            index_relative = index_path(name)
            index_file = repo_root / index_relative
            if not index_file.is_file():
                raise Finding(
                    f"{name}: an affected package has no index entry in this tree"
                )
            pr_entries = parse_index(
                index_file.read_text("utf-8", "replace"), f"submitted index for {name}"
            )
            base_blob = read_base_blob(base_root, index_relative)
            base_entries = (
                parse_index(base_blob.decode("utf-8", "replace"), f"base index for {name}")
                if base_blob is not None else {}
            )

            # Ownership applies to every affected package, including
            # index-only operations such as yanks.
            ownership_blob = read_base_blob(base_root, Path("ownership") / f"{name}.json")
            if ownership_blob is None:
                raise Finding(
                    f"{name}: no ownership record on the base branch; new packages "
                    "require an explicit enrollment decision (a separate, human-reviewed "
                    "ownership change)"
                )
            owners = json.loads(ownership_blob).get("owners", [])
            if args.author not in owners:
                raise Finding(
                    f"{name}: {args.author!r} is not an enrolled owner "
                    f"(owners: {', '.join(owners)})"
                )

            # The complete submitted index must preserve every published
            # record except authorized yank toggles.
            for version, entry in base_entries.items():
                submitted = pr_entries.get(version)
                if submitted is None:
                    raise Finding(
                        f"{index_relative}: published version {version} was removed "
                        "from the index; removals are not allowed (yank instead)"
                    )
                if submitted == entry:
                    continue
                differing = sorted(
                    key for key in set(entry) | set(submitted)
                    if entry.get(key) != submitted.get(key)
                )
                if differing == ["yanked"]:
                    continue  # an authorized yank toggle
                raise Finding(
                    f"{index_relative}: published version {version} record was "
                    f"modified (changed: {', '.join(differing)}); only yanking an "
                    "existing version is allowed"
                )

            new_versions = [version for version in pr_entries if version not in base_entries]
            for version in new_versions:
                entry = pr_entries[version]
                if not SEMVER.match(version):
                    raise Finding(f"{name}: {version!r} is not a valid Cargo version")
                relative = archive_path(name, version)
                if relative.as_posix() not in changed_archives:
                    raise Finding(
                        f"{index_relative}: new version {version} has no submitted "
                        "archive at the canonical path"
                    )
                blob = (repo_root / relative).read_bytes()
                submitted_sha = sha256_bytes(blob)
                if read_base_blob(base_root, relative) is not None:
                    raise Finding(
                        f"{relative}: version {version} is already published; "
                        "published versions are immutable — publish a new version instead"
                    )
                if entry.get("name") not in (None, name):
                    raise Finding(f"{relative}: index line names {entry.get('name')!r}")
                if entry.get("cksum") != submitted_sha:
                    raise Finding(
                        f"{relative}: index checksum {entry.get('cksum')!r} does not "
                        f"match the archive bytes ({submitted_sha})"
                    )
                for dependency in entry.get("deps", []):
                    if not dependency.get("name") or not dependency.get("req"):
                        raise Finding(
                            f"{relative}: malformed dependency entry in the index line"
                        )
                package, manifest_deps = extract_manifest(blob, relative.as_posix(), name, version)
                if package.get("version") != version:
                    raise Finding(
                        f"{relative}: manifest version {package.get('version')!r} does "
                        f"not match the published version {version!r}"
                    )
                compare_dependencies(name, version, entry.get("deps", []), manifest_deps)
                summary.append(
                    f"- `{name} {version}`: integrity verified "
                    f"(sha256 `{submitted_sha}`), owner `{args.author}`, "
                    "manifest and index dependencies agree."
                )
                report.append(
                    diff_report(name, version, blob, previous_version(base_root, name, version))
                )

            for relative in sorted(
                path for path in changed_archives
                if Path(path).parts[3] == name
            ):
                version = Path(relative).parts[4][: -len(".crate")]
                if version in base_entries:
                    blob = (repo_root / relative).read_bytes()
                    base_archive = read_base_blob(base_root, Path(relative))
                    if base_archive is None or sha256_bytes(base_archive) != sha256_bytes(blob):
                        raise Finding(
                            f"{relative}: version {version} is already published with "
                            "different bytes; published archives are immutable — "
                            "publish a new version instead"
                        )
                    summary.append(
                        f"- `{name} {version}`: identical re-submission of the "
                        "published archive (no-op)."
                    )

            if not new_versions and not any(
                Path(path).parts[3] == name for path in changed_archives
            ):
                summary.append(
                    f"- `{name}`: index-only change; authorized as an enrolled-owner "
                    "operation."
                )
        eligible = True
        summary.append("")
        summary.append(
            "Auto-merge eligibility: this pull request changes only publication "
            "paths, is owner-authorized for every affected package, and passed "
            "complete index and archive validation."
        )
        return finish(None)
    except Finding as finding:
        print(f"admission: {finding}", file=sys.stderr)
        return finish(finding)


if __name__ == "__main__":
    sys.exit(main())
