# phoxal/registry

This repository serves standard Cargo source packages through a sparse index and static `.crate` archives.
The sparse index is `sparse+https://phoxal.github.io/registry/`.
The package browser and archive host are at <https://phoxal.github.io/registry/>.

Packages may contain libraries, binaries, build scripts, Protobuf files, or application data according to their own Cargo manifests.
The registry does not impose Phoxal-specific archive paths or package shapes.
Cargo checks the archive checksum recorded in the sparse index when it downloads a package.

`cargo phoxal publish` can prepare a package submission for review.
Publishing, ownership policy, and release automation are separate from the build-script API proof.
The existing `config.json`, `margo-config.toml`, and Pages deployment serve the registry.

See <https://phoxal.com> for public Phoxal documentation.
