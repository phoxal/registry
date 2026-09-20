# phoxal/registry

This repository is the reviewed, read-only Cargo registry for Phoxal source packages.

The registry serves library, proc-macro, service, component, configuration-preset, simulator, and application packages as source `.crate` archives.

It is not a store of precompiled robot executables.

The sparse Cargo index is `sparse+https://phoxal.github.io/registry/`.

The package browser and archive host are available at <https://phoxal.github.io/registry/>.

Consumers configure the `phoxal` registry alias in their framework, developer, or robot Cargo workspace.

The archived `phoxal-cli` is not required to resolve or install packages.

Every package has an independent semantic version, immutable archive checksum, and exact sparse-index record.

Rewritten Phoxal packages are not published to crates.io unless a later release decision explicitly changes that boundary.

## Reviewed publication

`cargo phoxal publish component <name>` and `cargo phoxal publish service <name>` prepare the exact Cargo archive and submit a pull request to this repository.

The command may also publish a configuration preset through the service publication path.

Dry runs produce the archive, checksum, asset inventory, and review evidence without GitHub authentication or remote mutation.

Normal submission returns a pending-review result and pull request URL.

Only a merged archive and index pair deployed through GitHub Pages is reported as published.

Registry admission checks validate package identity, canonical Cargo paths, dependency registries, archive checksums, archive contents, reviewed package kind, standard package structure, assets, unsafe links, and source provenance.

Developers do not declare a `[package.metadata.phoxal]` table.
The publication command records the selected role in immutable review provenance, while root `component.yaml` or `service.yaml` definitions and Cargo target shape independently validate that role.

The archive and index are checked as the exact bytes that consumers will receive.

Each new package version has an immutable `provenance/<name>/<version>.json` record containing its source identity, archive checksum, package kind, preparation tool, and exhaustive file inventory.

The first approved publication of a name also has an immutable `ownership/<name>.json` record that reserves the name and identifies its owners.

Existing ownership and provenance records cannot be modified, deleted, or renamed.

Published archives and substantive index records are append-only.

A reviewed withdrawal may change exactly one existing index record from `"yanked": false` to `"yanked": true` without changing any other field or archive byte.

Yanking does not delete an archive or rewrite a consumer lockfile.

Run the trusted checks against a proposed pull request with:

```sh
python3 .github/scripts/check_append_only.py BASE HEAD
python3 .github/scripts/check_admission.py BASE HEAD
```

For each valid new archive, pull-request automation also uploads `registry-review-evidence`.
It contains the complete safely extracted prior and proposed package trees, exhaustive inventories and checksums, and a Git binary diff made from those exact archive bytes.
The first publication is diffed against an empty tree so every packaged source and configuration file is visible.

The append-only check protects every introduced commit, while admission validates the final reviewed tree.

The current `config.json`, `margo-config.toml`, and GitHub Pages deployment preserve the existing sparse-index and static archive serving path.

Historical archive and index bytes remain unchanged when the registry format or admission tooling evolves.

See <https://phoxal.com> for public Phoxal documentation.
