#!/usr/bin/env python3
"""Validate reviewed Cargo package additions to the Phoxal registry.

The registry is a static Cargo registry, so admission happens against the exact
bytes proposed by a pull request.  This checker deliberately does not run code
from an archive.  It validates the archive structure, normalized Cargo
metadata, sparse-index record, immutable provenance, and ownership record.

Usage::

    python3 .github/scripts/check_admission.py BASE HEAD

``BASE`` and ``HEAD`` are git revisions.  The command checks the complete
proposed tree at ``HEAD`` and every introduced package/archive/index change in
the range.  A package submission consists of an archive, an index record, a
``provenance/<name>/<version>.json`` record, and an
``ownership/<name>.json`` record when the name has not been reserved before.
The provenance and ownership records are registry metadata, not Cargo index
inputs, and are immutable after admission.
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # Python 3.9 on the supported GitHub runner.
    try:
        import tomli as tomllib  # type: ignore[import-not-found]
    except ImportError:  # The local runner currently provides ``toml``.
        try:
            import toml as _toml  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - defensive CI diagnostic.
            tomllib = None  # type: ignore[assignment]
        else:
            tomllib = _toml  # type: ignore[assignment]


PHOXAL_INDEX = "sparse+https://phoxal.github.io/registry/"
CRATES_IO_INDEX = "https://github.com/rust-lang/crates.io-index"
ALLOWED_MODES = {"100644", "100755"}
METADATA_FILES = {
    "config.json",
    "margo-config.toml",
    "index.html",
    "README.md",
    ".nojekyll",
    ".gitignore",
}
METADATA_PREFIXES = ("assets/", ".github/")
IMMUTABLE_METADATA_PREFIXES = ("provenance/", "ownership/")
KNOWN_KINDS = {
    "application",
    "component",
    "library",
    "preset",
    "proc-macro",
    "service",
    "simulator",
    "tool",
}
KNOWN_SOURCE_ORIGINS = {"github", "git", "local", "path"}
PACKAGE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_PATH_BYTES = 4096


class AdmissionError(ValueError):
    """A package or registry record violates an admission rule."""


def archive_inventory(files: Mapping[str, bytes]) -> list[dict[str, Any]]:
    """Return deterministic review metadata for extracted archive files."""

    return [
        {
            "path": path,
            "size": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(),
        }
        for path, contents in sorted(files.items())
    ]


@dataclass(frozen=True)
class Problem:
    path: str
    message: str


@dataclass
class ArchiveReport:
    name: str
    version: str
    kind: str
    files: dict[str, bytes]
    package: dict[str, Any]
    dependencies: dict[str, Any]

    @property
    def inventory(self) -> list[dict[str, Any]]:
        return archive_inventory(self.files)


def canonical_index_path(name: str) -> str:
    """Return Cargo's sparse-index path for a lowercase package name."""

    lower = name.lower()
    if len(lower) == 1:
        return f"1/{lower}"
    if len(lower) == 2:
        return f"2/{lower}"
    if len(lower) == 3:
        return f"3/{lower}"
    return f"{lower[:2]}/{lower[2:4]}/{lower}"


def canonical_archive_path(name: str, version: str) -> str:
    return f"crates/{canonical_index_path(name)}/{version}.crate"


def provenance_path(name: str, version: str) -> str:
    return f"provenance/{name}/{version}.json"


def ownership_path(name: str) -> str:
    return f"ownership/{name}.json"


def is_archive_path(path: str) -> bool:
    return path.startswith("crates/")


def is_provenance_path(path: str) -> bool:
    return path.startswith("provenance/")


def is_ownership_path(path: str) -> bool:
    return path.startswith("ownership/")


def is_index_path(path: str) -> bool:
    if is_archive_path(path) or is_provenance_path(path) or is_ownership_path(path):
        return False
    if path in METADATA_FILES or path.startswith(METADATA_PREFIXES):
        return False
    parts = path.split("/")
    return (
        (len(parts) == 2 and parts[0] in {"1", "2", "3"} and bool(parts[1]))
        or (len(parts) == 3 and all(parts))
    )


def _validate_name(name: Any, context: str) -> str:
    if not isinstance(name, str) or not PACKAGE_NAME_RE.fullmatch(name):
        raise AdmissionError(
            f"{context} must be a lowercase Cargo package name, got {name!r}"
        )
    return name


def _validate_version(version: Any, context: str) -> str:
    if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
        raise AdmissionError(f"{context} must be a semantic version, got {version!r}")
    return version


def _validate_sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AdmissionError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _validate_relative_path(value: Any, context: str, *, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > MAX_PATH_BYTES:
        raise AdmissionError(f"{context} must be a short relative path")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise AdmissionError(f"{context} contains an unsafe path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".."} or (part == "." and not allow_dot) for part in parts):
        raise AdmissionError(f"{context} contains an unsafe path: {value!r}")
    if posixpath.normpath(value) != value:
        raise AdmissionError(f"{context} is not normalized: {value!r}")
    return value


def _parse_toml(data: bytes, path: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdmissionError(f"{path} is not UTF-8: {error}") from error
    if tomllib is None:  # pragma: no cover - only used on an incomplete runner.
        raise AdmissionError(
            "the admission runner needs a TOML parser (tomllib, tomli, or toml)"
        )
    try:
        parsed = tomllib.loads(text)
    except Exception as error:  # tomllib and toml use different exception types.
        raise AdmissionError(f"{path} is malformed TOML: {error}") from error
    if not isinstance(parsed, dict):
        raise AdmissionError(f"{path} did not produce a TOML table")
    return parsed


def _metadata_table(package: Mapping[str, Any], path: str) -> dict[str, Any]:
    metadata = package.get("metadata", {})
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise AdmissionError(f"{path} package.metadata must be a table")
    phoxal = metadata.get("phoxal", {})
    if phoxal is None:
        return {}
    if not isinstance(phoxal, Mapping):
        raise AdmissionError(f"{path} package.metadata.phoxal must be a table")
    return dict(phoxal)


def _target_shape(manifest: Mapping[str, Any]) -> tuple[bool, bool, bool]:
    lib = manifest.get("lib")
    bins = manifest.get("bin")
    has_lib = isinstance(lib, Mapping)
    has_bins = isinstance(bins, list) and bool(bins)
    has_proc_macro = has_lib and lib.get("proc-macro") is True
    return has_lib, has_bins, has_proc_macro


def _validate_dependencies(manifest: Mapping[str, Any], path: str) -> dict[str, Any]:
    dependencies: dict[str, Any] = {}
    for table_name in ("dependencies", "build-dependencies", "dev-dependencies"):
        table = manifest.get(table_name, {})
        if table is None:
            continue
        if not isinstance(table, Mapping):
            raise AdmissionError(f"{path} [{table_name}] must be a table")
        for name, spec in table.items():
            if not isinstance(name, str):
                raise AdmissionError(f"{path} has a non-string dependency name")
            if isinstance(spec, str):
                spec = {"version": spec}
            if not isinstance(spec, Mapping):
                raise AdmissionError(f"{path} dependency {name!r} is not a table/string")
            spec = dict(spec)
            if "path" in spec or "git" in spec:
                raise AdmissionError(
                    f"{path} dependency {name!r} retains a path/git source"
                )
            if "registry" in spec and "registry-index" in spec:
                raise AdmissionError(
                    f"{path} dependency {name!r} declares both registry forms"
                )
            registry = spec.get("registry-index", spec.get("registry"))
            if registry is not None and not isinstance(registry, str):
                raise AdmissionError(
                    f"{path} dependency {name!r} has a non-string registry"
                )
            if registry not in {None, PHOXAL_INDEX, CRATES_IO_INDEX}:
                raise AdmissionError(
                    f"{path} dependency {name!r} uses an unknown registry {registry!r}"
                )
            if name.startswith("phoxal") and registry != PHOXAL_INDEX:
                raise AdmissionError(
                    f"{path} internal dependency {name!r} must use {PHOXAL_INDEX}"
                )
            if "version" not in spec or not isinstance(spec["version"], str):
                raise AdmissionError(
                    f"{path} dependency {name!r} needs a version requirement"
                )
            dependencies.setdefault(name, []).append(
                {"table": table_name, "spec": spec}
            )
    return dependencies


def _validate_kind_shape(
    kind: str,
    manifest: Mapping[str, Any],
    files: Mapping[str, bytes],
    dependencies: Mapping[str, Any],
    path: str,
) -> None:
    has_lib, has_bins, has_proc_macro = _target_shape(manifest)
    if kind == "service":
        if not (has_lib and has_bins):
            raise AdmissionError(f"{path} service packages must expose both lib and bin")
    if kind == "component":
        generated = "_cargo/lib.rs" in files
        if not has_lib:
            raise AdmissionError(f"{path} component packages must expose a lib target")
        if "component.yaml" not in files:
            raise AdmissionError(f"{path} component packages must contain root component.yaml")
        if not has_bins and not generated:
            raise AdmissionError(
                f"{path} targetless component data must contain the staged _cargo/lib.rs"
            )
    elif kind == "preset":
        if has_bins:
            raise AdmissionError(f"{path} configuration presets cannot expose a bin")
        if "service.yaml" not in files:
            raise AdmissionError(f"{path} presets must contain root service.yaml")
        if not any(
            any(item["table"] == "dependencies" for item in specs)
            for specs in dependencies.values()
        ):
            raise AdmissionError(f"{path} presets must depend on their real implementation")
    elif kind == "library" and not has_lib:
        raise AdmissionError(f"{path} library packages must expose a lib target")
    elif kind == "proc-macro" and not has_proc_macro:
        raise AdmissionError(f"{path} proc-macro packages need lib.proc-macro = true")
    elif kind in {"application", "simulator", "tool"} and not has_bins:
        raise AdmissionError(f"{path} {kind} packages must expose a bin target")


def extract_archive_files(
    archive: bytes, expected_name: str, expected_version: str
) -> dict[str, bytes]:
    """Safely extract regular files from one identity-bound Cargo archive."""

    expected_name = _validate_name(expected_name, "archive name")
    expected_version = _validate_version(expected_version, "archive version")
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise AdmissionError(
            f"{expected_name}-{expected_version}.crate exceeds the compressed size limit"
        )

    root = f"{expected_name}-{expected_version}/"
    files: dict[str, bytes] = {}
    total_size = 0
    try:
        tar = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")
    except (tarfile.TarError, OSError) as error:
        raise AdmissionError(f"archive is not a valid gzip tar archive: {error}") from error

    directory_names: set[str] = set()
    with tar:
        members = tar.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise AdmissionError("archive contains too many entries")
        for member in members:
            raw_name = member.name
            if len(raw_name.encode(errors="surrogatepass")) > MAX_PATH_BYTES:
                raise AdmissionError(f"archive member path is too long: {raw_name!r}")
            if "\\" in raw_name or "\x00" in raw_name:
                raise AdmissionError(f"archive member path is unsafe: {raw_name!r}")
            member_name = raw_name.rstrip("/")
            if not member_name.startswith(root) or member_name == root[:-1]:
                raise AdmissionError(
                    f"archive member {raw_name!r} is outside its {root!r} root"
                )
            relative = member_name[len(root) :]
            _validate_relative_path(relative, "archive member")
            if relative in files or relative in directory_names:
                raise AdmissionError(f"archive contains duplicate member {relative!r}")
            if member.issym() or member.islnk() or member.isdev():
                raise AdmissionError(f"archive member {raw_name!r} is an unsafe link/device")
            if member.isdir():
                directory_names.add(relative)
                continue
            if not member.isreg():
                raise AdmissionError(f"archive member {raw_name!r} is not a regular file")
            if member.size < 0 or member.size > MAX_UNPACKED_BYTES:
                raise AdmissionError(f"archive member {relative!r} has an invalid size")
            total_size += member.size
            if total_size > MAX_UNPACKED_BYTES:
                raise AdmissionError("archive exceeds the uncompressed size limit")
            stream = tar.extractfile(member)
            if stream is None:
                raise AdmissionError(f"archive member {relative!r} has no readable body")
            contents = stream.read(member.size + 1)
            if len(contents) != member.size:
                raise AdmissionError(f"archive member {relative!r} changed while reading")
            files[relative] = contents

    return files


def inspect_archive(
    archive: bytes,
    expected_name: str,
    expected_version: str,
    expected_kind: str | None = None,
) -> ArchiveReport:
    """Inspect one current Cargo archive without executing submitted code."""

    files = extract_archive_files(archive, expected_name, expected_version)

    manifest_bytes = files.get("Cargo.toml")
    if manifest_bytes is None:
        raise AdmissionError("archive does not contain Cargo.toml")
    manifest = _parse_toml(manifest_bytes, "Cargo.toml")
    package = manifest.get("package")
    if not isinstance(package, Mapping):
        raise AdmissionError("Cargo.toml does not contain a [package] table")
    package = dict(package)
    name = _validate_name(package.get("name"), "Cargo.toml package.name")
    version = _validate_version(package.get("version"), "Cargo.toml package.version")
    if name != expected_name or version != expected_version:
        raise AdmissionError(
            "archive identity disagrees with its path/index: "
            f"Cargo.toml has {name}-{version}, expected {expected_name}-{expected_version}"
        )
    publish = package.get("publish")
    if publish != ["phoxal"]:
        raise AdmissionError(
            "registry packages must declare publish = [\"phoxal\"] in the normalized manifest"
        )
    metadata = _metadata_table(package, "Cargo.toml")
    if expected_kind is None:
        kind = metadata.get("kind")
    else:
        kind = expected_kind
        if metadata:
            raise AdmissionError(
                "Cargo.toml must not declare package.metadata.phoxal; "
                "the reviewed provenance and standard package structure own package classification"
            )
    if not isinstance(kind, str) or kind not in KNOWN_KINDS:
        raise AdmissionError(
            "package kind must be one of "
            + ", ".join(sorted(KNOWN_KINDS))
        )
    dependencies = _validate_dependencies(manifest, "Cargo.toml")
    _validate_kind_shape(kind, manifest, files, dependencies, "Cargo.toml")
    return ArchiveReport(
        name=name,
        version=version,
        kind=kind,
        files=files,
        package=package,
        dependencies=dependencies,
    )


def parse_index_records(data: bytes, path: str) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdmissionError(f"{path} is not UTF-8: {error}") from error
    records: list[dict[str, Any]] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            raise AdmissionError(f"{path}:{line_number} contains a blank index line")
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as error:
            raise AdmissionError(f"{path}:{line_number} is malformed JSON: {error}") from error
        if not isinstance(record, dict):
            raise AdmissionError(f"{path}:{line_number} is not a JSON object")
        records.append(record)
    return records


def validate_index_record(
    record: Mapping[str, Any],
    index_path: str,
    archive: bytes | None,
    *,
    strict_internal_dependencies: bool = True,
) -> None:
    name = _validate_name(record.get("name"), f"{index_path} name")
    version = _validate_version(record.get("vers"), f"{index_path} version")
    if index_path != canonical_index_path(name):
        raise AdmissionError(
            f"index path {index_path!r} is not Cargo's canonical path for {name!r}"
        )
    _validate_sha256(record.get("cksum"), f"{index_path} checksum")
    if archive is not None:
        actual = hashlib.sha256(archive).hexdigest()
        if record["cksum"] != actual:
            raise AdmissionError(
                f"{index_path} {name}-{version} checksum does not match its archive"
            )
    deps = record.get("deps")
    if not isinstance(deps, list):
        raise AdmissionError(f"{index_path} deps must be a list")
    for number, dep in enumerate(deps, 1):
        if not isinstance(dep, Mapping):
            raise AdmissionError(f"{index_path} dependency {number} is not an object")
        required = {
            "name",
            "req",
            "features",
            "optional",
            "default_features",
            "kind",
            "registry",
        }
        missing = required - dep.keys()
        if missing:
            raise AdmissionError(
                f"{index_path} dependency {number} is missing {', '.join(sorted(missing))}"
            )
        _validate_name(dep["name"], f"{index_path} dependency name")
        if not isinstance(dep["req"], str) or not dep["req"]:
            raise AdmissionError(f"{index_path} dependency {number} has no requirement")
        if not isinstance(dep["features"], list) or not all(
            isinstance(value, str) for value in dep["features"]
        ):
            raise AdmissionError(f"{index_path} dependency {number} features are invalid")
        if not isinstance(dep["optional"], bool) or not isinstance(
            dep["default_features"], bool
        ):
            raise AdmissionError(f"{index_path} dependency {number} flags are invalid")
        if dep["kind"] not in {"normal", "build", "dev"}:
            raise AdmissionError(f"{index_path} dependency {number} kind is invalid")
        registry = dep["registry"]
        if registry is not None and not isinstance(registry, str):
            raise AdmissionError(f"{index_path} dependency {number} registry is invalid")
        if registry not in {None, PHOXAL_INDEX, CRATES_IO_INDEX}:
            raise AdmissionError(f"{index_path} dependency {number} registry is invalid")
        if strict_internal_dependencies and dep["name"].startswith("phoxal"):
            if registry is not None:
                raise AdmissionError(
                    f"{index_path} internal dependency {dep['name']!r} is not same-registry"
                )
    if not isinstance(record.get("features"), dict):
        raise AdmissionError(f"{index_path} features must be an object")
    if not all(
        isinstance(key, str)
        and isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        for key, value in record["features"].items()
    ):
        raise AdmissionError(f"{index_path} feature values must be string arrays")
    if not isinstance(record.get("yanked"), bool):
        raise AdmissionError(f"{index_path} yanked must be boolean")
    if (
        not isinstance(record.get("v"), int)
        or isinstance(record.get("v"), bool)
        or record["v"] not in {1, 2}
    ):
        raise AdmissionError(f"{index_path} index format version must be 1 or 2")
    for key in ("rust_version", "links", "pubtime"):
        if key in record and not isinstance(record[key], str):
            raise AdmissionError(f"{index_path} {key} must be a string when present")
    for key in ("features2",):
        if key in record and not isinstance(record[key], dict):
            raise AdmissionError(f"{index_path} {key} must be an object when present")


def parse_provenance(
    data: bytes,
    path: str,
    expected_name: str,
    expected_version: str,
) -> dict[str, Any]:
    """Parse the reviewed package identity and kind before archive inspection."""

    try:
        record = json.loads(data)
    except json.JSONDecodeError as error:
        raise AdmissionError(f"{path} is malformed JSON: {error}") from error
    if not isinstance(record, Mapping):
        raise AdmissionError(f"{path} must contain a JSON object")
    if record.get("name") != expected_name or record.get(
        "version", record.get("vers")
    ) != expected_version:
        raise AdmissionError(f"{path} package identity does not match its path")
    kind = record.get("kind")
    if not isinstance(kind, str) or kind not in KNOWN_KINDS:
        raise AdmissionError(
            f"{path} package kind must be one of " + ", ".join(sorted(KNOWN_KINDS))
        )
    return dict(record)


def validate_provenance(
    data: bytes,
    path: str,
    archive_path: str,
    archive_bytes: bytes,
    archive: ArchiveReport,
    ownership: Mapping[str, Any] | None,
) -> None:
    """Validate provenance against the original archive bytes."""

    expected_path = provenance_path(archive.name, archive.version)
    if path != expected_path:
        raise AdmissionError(f"provenance path must be {expected_path!r}")
    record = parse_provenance(data, path, archive.name, archive.version)
    if record.get("kind") != archive.kind:
        raise AdmissionError(f"{path} package kind does not match Cargo.toml")
    if record.get("archive", record.get("archive_path")) != archive_path:
        raise AdmissionError(f"{path} archive path does not match the index record")
    digest = _validate_sha256(record.get("archive_sha256"), f"{path} archive_sha256")
    if digest != hashlib.sha256(archive_bytes).hexdigest():
        raise AdmissionError(f"{path} archive checksum does not match the submitted archive")
    _validate_source_and_inventory(record, path, archive, ownership)


def _validate_source_and_inventory(
    record: Mapping[str, Any],
    path: str,
    archive: ArchiveReport,
    ownership: Mapping[str, Any] | None,
) -> None:
    source = record.get("source")
    if not isinstance(source, Mapping):
        raise AdmissionError(f"{path} source provenance must be an object")
    origin = source.get("origin", source.get("kind"))
    if not isinstance(origin, str) or origin not in KNOWN_SOURCE_ORIGINS:
        raise AdmissionError(
            f"{path} source provenance origin must be one of "
            + ", ".join(sorted(KNOWN_SOURCE_ORIGINS))
        )
    source_path = source.get("path", source.get("package"))
    _validate_relative_path(source_path, f"{path} source path", allow_dot=True)
    revision = source.get("revision", source.get("commit", source.get("digest")))
    if not isinstance(revision, str) or not revision:
        raise AdmissionError(f"{path} source provenance needs a revision or digest")
    preparation = source.get("preparation", source.get("tool"))
    if not isinstance(preparation, str) or not preparation:
        raise AdmissionError(f"{path} source provenance needs preparation/tool identity")
    inventory = record.get("assets")
    if not isinstance(inventory, list):
        raise AdmissionError(f"{path} must inventory every archive file in assets")
    expected = set(archive.files)
    seen: set[str] = set()
    for item in inventory:
        if not isinstance(item, Mapping):
            raise AdmissionError(f"{path} asset inventory entries must be objects")
        item_path = _validate_relative_path(item.get("path"), f"{path} asset path")
        if item_path in seen:
            raise AdmissionError(f"{path} inventories asset {item_path!r} twice")
        seen.add(item_path)
        if item_path not in archive.files:
            raise AdmissionError(f"{path} inventories missing archive path {item_path!r}")
        digest = _validate_sha256(item.get("sha256"), f"{path} asset {item_path}")
        if digest != hashlib.sha256(archive.files[item_path]).hexdigest():
            raise AdmissionError(f"{path} asset {item_path!r} checksum does not match")
        if (
            not isinstance(item.get("size"), int)
            or isinstance(item.get("size"), bool)
            or item["size"] != len(archive.files[item_path])
        ):
            raise AdmissionError(f"{path} asset {item_path!r} size does not match")
    if seen != expected:
        missing = ", ".join(sorted(expected - seen))
        extra = ", ".join(sorted(seen - expected))
        detail = f"missing: {missing}" if missing else f"unknown: {extra}"
        raise AdmissionError(f"{path} asset inventory is not exhaustive ({detail})")
    publisher = record.get("publisher")
    if publisher is not None:
        if not isinstance(publisher, str) or not publisher:
            raise AdmissionError(f"{path} publisher must be a non-empty identity")
        if ownership is not None and publisher not in ownership["owners"]:
            raise AdmissionError(f"{path} publisher is not an owner of the package name")


def validate_ownership(data: bytes, path: str, expected_name: str) -> dict[str, Any]:
    expected_path = ownership_path(expected_name)
    if path != expected_path:
        raise AdmissionError(f"ownership path must be {expected_path!r}")
    try:
        record = json.loads(data)
    except json.JSONDecodeError as error:
        raise AdmissionError(f"{path} is malformed JSON: {error}") from error
    if not isinstance(record, dict):
        raise AdmissionError(f"{path} must contain a JSON object")
    name = _validate_name(record.get("name"), f"{path} name")
    if name != expected_name:
        raise AdmissionError(f"{path} name does not match its path")
    owners = record.get("owners")
    if (
        not isinstance(owners, list)
        or not owners
        or not all(isinstance(owner, str) and owner for owner in owners)
        or len(set(owners)) != len(owners)
    ):
        raise AdmissionError(f"{path} owners must be a non-empty unique string list")
    if record.get("reserved") is not True:
        raise AdmissionError(f"{path} must reserve the package name explicitly")
    if "kind" in record and (
        not isinstance(record["kind"], str) or record["kind"] not in KNOWN_KINDS
    ):
        raise AdmissionError(f"{path} kind is not recognized")
    return record


def yanked_only_change(old: bytes, new: bytes) -> bool:
    """Return true only for one existing record changing false to true."""

    try:
        old_records = parse_index_records(old, "old index")
        new_records = parse_index_records(new, "new index")
    except AdmissionError:
        return False
    if len(old_records) != len(new_records):
        return False
    changed = 0
    for before, after in zip(old_records, new_records):
        if before == after:
            continue
        if set(before) != set(after) or any(
            before[key] != after[key] for key in before if key != "yanked"
        ):
            return False
        if before.get("yanked") is not False or after.get("yanked") is not True:
            return False
        changed += 1
    return changed == 1


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def _git_blob(revision: str, path: str) -> bytes | None:
    result = subprocess.run(["git", "show", f"{revision}:{path}"], capture_output=True)
    return result.stdout if result.returncode == 0 else None


def _git_mode(revision: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "ls-tree", revision, "--", path], capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.split(None, 1)[0]


def _changed_paths(base: str, head: str) -> list[tuple[str, str, str, str]]:
    changes: list[tuple[str, str, str, str]] = []
    for commit in _git("rev-list", "--reverse", f"{base}..{head}").split():
        parent = f"{commit}^"
        lines = _git(
            "diff-tree", "-r", "-M", "--no-commit-id", "--root", parent, commit
        ).splitlines()
        for line in lines:
            if not line.startswith(":"):
                continue
            meta, _, paths = line.partition("\t")
            fields = meta[1:].split()
            if len(fields) < 5:
                continue
            old_mode, new_mode, _old_sha, _new_sha, status = fields[:5]
            names = paths.split("\t")
            old_path = names[0]
            new_path = names[-1]
            changes.append((commit, old_path, new_path, status[0]))
    return changes


def _head_files(head: str, paths: Iterable[str]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in paths:
        value = _git_blob(head, path)
        if value is not None:
            result[path] = value
    return result


def _records_by_identity(data: bytes, path: str) -> dict[tuple[str, str], dict[str, Any]]:
    records = parse_index_records(data, path)
    output: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        name = record.get("name")
        version = record.get("vers")
        if not isinstance(name, str) or not isinstance(version, str):
            raise AdmissionError(f"{path} contains a record without string identity")
        identity = (name, version)
        if identity in output:
            raise AdmissionError(f"{path} declares {name}-{version} more than once")
        output[identity] = record
    return output


def validate_range(base: str, head: str) -> list[Problem]:
    """Validate a proposed registry PR and return all admission problems."""

    problems: list[Problem] = []
    changes = _changed_paths(base, head)
    requested_paths: set[str] = set()
    for _commit, old_path, new_path, _status in changes:
        requested_paths.update((old_path, new_path))
        candidate = new_path
        if is_archive_path(candidate):
            match = re.fullmatch(
                r"crates/[^/]+/[^/]+/([^/]+)/([^/]+)\.crate", candidate
            )
            if match:
                name, version = match.groups()
                requested_paths.update(
                    (
                        canonical_index_path(name),
                        provenance_path(name, version),
                        ownership_path(name),
                    )
                )
        elif is_index_path(candidate):
            requested_paths.add(candidate)
        elif is_provenance_path(candidate):
            match = re.fullmatch(r"provenance/([^/]+)/([^/]+)\.json", candidate)
            if match:
                name, version = match.groups()
                requested_paths.update(
                    (
                        canonical_index_path(name),
                        canonical_archive_path(name, version),
                        ownership_path(name),
                    )
                )
        elif is_ownership_path(candidate):
            match = re.fullmatch(r"ownership/([^/]+)\.json", candidate)
            if match:
                requested_paths.add(canonical_index_path(match.group(1)))
    head_files = _head_files(head, requested_paths)
    base_files = _head_files(base, requested_paths)

    added_archives: dict[tuple[str, str], tuple[str, bytes]] = {}
    changed_indexes: set[str] = set()
    added_provenance: set[str] = set()
    added_ownership: set[str] = set()

    for _commit, old_path, new_path, status in changes:
        if status == "A" and (
            is_archive_path(new_path)
            or is_index_path(new_path)
            or is_provenance_path(new_path)
            or is_ownership_path(new_path)
        ):
            mode = _git_mode(head, new_path)
            if mode not in ALLOWED_MODES:
                problems.append(
                    Problem(new_path, "registry content must be a regular file, not a symlink or gitlink")
                )
                continue
        if is_archive_path(old_path) or is_archive_path(new_path):
            if status != "A":
                problems.append(
                    Problem(new_path, "published archives may only be added, never modified/deleted/renamed")
                )
                continue
            match = re.fullmatch(
                r"crates/([^/]+)/([^/]+)/([^/]+)/([^/]+)\.crate", new_path
            )
            if not match:
                problems.append(Problem(new_path, "archive path is not a canonical Cargo path"))
                continue
            _first, _second, name, version = match.groups()
            try:
                _validate_name(name, f"{new_path} package name")
                _validate_version(version, f"{new_path} package version")
            except AdmissionError as error:
                problems.append(Problem(new_path, str(error)))
                continue
            if new_path != canonical_archive_path(name, version):
                problems.append(Problem(new_path, "archive path is not canonical for its package"))
                continue
            archive = head_files.get(new_path)
            if archive is None:
                problems.append(Problem(new_path, "added archive is missing from the head tree"))
                continue
            added_archives[(name, version)] = (new_path, archive)
        elif is_index_path(new_path):
            changed_indexes.add(new_path)
        elif is_provenance_path(new_path):
            if status != "A":
                problems.append(Problem(new_path, "provenance records are immutable after admission"))
            else:
                added_provenance.add(new_path)
        elif is_ownership_path(new_path):
            if status != "A":
                problems.append(Problem(new_path, "ownership records are immutable after admission"))
            else:
                added_ownership.add(new_path)

    # Validate every changed index, including records added in an earlier
    # commit than their archive.  The PR head is the reviewable tree.
    for path in sorted(changed_indexes):
        new_data = head_files.get(path)
        if new_data is None:
            problems.append(Problem(path, "index file is missing from the head tree"))
            continue
        old_data = base_files.get(path, b"")
        for commit, old_path, new_path, _status in changes:
            if path not in {old_path, new_path}:
                continue
            before = _git_blob(f"{commit}^", old_path) or b""
            after = _git_blob(commit, new_path) or b""
            if not after.startswith(before) and not yanked_only_change(before, after):
                problems.append(
                    Problem(
                        path,
                        f"index change in {commit[:9]} rewrites existing bytes; "
                        "only appended records or one false-to-true yanked update are allowed",
                    )
                )
        try:
            old_records = _records_by_identity(old_data, path) if old_data else {}
            new_records = _records_by_identity(new_data, path)
            for identity, record in new_records.items():
                name, version = identity
                archive_path = canonical_archive_path(name, version)
                archive_bytes = head_files.get(archive_path)
                is_new = identity not in old_records
                validate_index_record(
                    record,
                    path,
                    archive_bytes,
                    strict_internal_dependencies=is_new,
                )
                if is_new and archive_bytes is None:
                    raise AdmissionError(f"{archive_path} is missing for the new index record")
                if is_new:
                    provenance = provenance_path(name, version)
                    provenance_bytes = head_files.get(provenance)
                    if provenance_bytes is None:
                        raise AdmissionError(f"{provenance} is required for a reviewed package")
                    provenance_record = parse_provenance(
                        provenance_bytes, provenance, name, version
                    )
                    archive_report = inspect_archive(
                        archive_bytes,  # type: ignore[arg-type]
                        name,
                        version,
                        provenance_record["kind"],
                    )
                    owner_path = ownership_path(name)
                    owner_bytes = head_files.get(owner_path)
                    owner_record: dict[str, Any] | None = None
                    if owner_bytes is not None:
                        owner_record = validate_ownership(owner_bytes, owner_path, name)
                    else:
                        raise AdmissionError(
                            f"{owner_path} is required for every newly admitted version"
                        )
                    if owner_record.get("kind") not in {None, archive_report.kind}:
                        raise AdmissionError(
                            f"{owner_path} package kind does not match the archive"
                        )
                    validate_provenance(
                        provenance_bytes,
                        provenance,
                        archive_path,
                        archive_bytes,
                        archive_report,
                        owner_record,
                    )
        except AdmissionError as error:
            problems.append(Problem(path, str(error)))

    # Every new archive must have a corresponding index record.  This catches
    # an archive-only PR even when the index is added in a later commit.
    for (name, version), (path, archive_bytes) in sorted(added_archives.items()):
        index_path = canonical_index_path(name)
        data = head_files.get(index_path)
        if data is None:
            problems.append(Problem(path, f"index {index_path} is missing for the new archive"))
            continue
        try:
            records = _records_by_identity(data, index_path)
            record = records.get((name, version))
            if record is None:
                raise AdmissionError(f"index has no record for {name}-{version}")
            validate_index_record(record, index_path, archive_bytes)
        except AdmissionError as error:
            problems.append(Problem(path, str(error)))

    # Validate newly added ownership records even if an index record is staged
    # in a later commit or the package is part of a multi-package PR.
    for path in sorted(added_ownership):
        match = re.fullmatch(r"ownership/([^/]+)\.json", path)
        if not match:
            problems.append(Problem(path, "ownership path must be ownership/<name>.json"))
            continue
        try:
            validate_ownership(head_files[path], path, match.group(1))
        except AdmissionError as error:
            problems.append(Problem(path, str(error)))

    # Ensure every provenance record added in the PR points at an archive and
    # index record, even when another validator did not see that index as a
    # changed path because the package was already present in the base tree.
    for path in sorted(added_provenance):
        match = re.fullmatch(r"provenance/([^/]+)/([^/]+)\.json", path)
        if not match:
            problems.append(Problem(path, "provenance path must be provenance/<name>/<version>.json"))
            continue
        name, version = match.groups()
        archive_path = canonical_archive_path(name, version)
        archive_bytes = head_files.get(archive_path)
        if archive_bytes is None:
            problems.append(Problem(path, f"{archive_path} is missing for provenance"))
            continue
        try:
            provenance_record = parse_provenance(
                head_files[path], path, name, version
            )
            report = inspect_archive(
                archive_bytes, name, version, provenance_record["kind"]
            )
            owner_path = ownership_path(name)
            owner = head_files.get(owner_path)
            if owner is None:
                raise AdmissionError(f"{owner_path} is required for provenance")
            owner_record = validate_ownership(owner, owner_path, name)
            validate_provenance(
                head_files[path], path, archive_path, archive_bytes, report, owner_record
            )
        except AdmissionError as error:
            problems.append(Problem(path, str(error)))

    return problems


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 2:
        print("usage: check_admission.py BASE HEAD", file=sys.stderr)
        return 2
    try:
        problems = validate_range(args[0], args[1])
    except subprocess.CalledProcessError as error:
        print(f"::error::git inspection failed: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(f"::error file={problem.path}::{problem.message}")
    if problems:
        print(f"registry admission: {len(problems)} problem(s)")
        return 1
    print("registry admission: proposed package changes are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
