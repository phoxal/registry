# phoxal/registry

This repository serves standard Cargo source packages through a sparse index and static `.crate` archives.
The sparse index is `sparse+https://phoxal.github.io/registry/`.
The package browser and archive host are at <https://phoxal.github.io/registry/>.

Packages may contain libraries, binaries, build scripts, Protobuf files, or application data according to their own Cargo manifests.
The registry does not impose Phoxal-specific archive paths or package shapes.
Cargo checks the archive checksum recorded in the sparse index when it downloads a package.

`cargo phoxal publish` prepares a package submission as a pull request.

Every submission pull request passes the `admission` workflow: archive
checksum and manifest identity checks, immutability of published versions,
owner authorization from `ownership/` on the base branch, and a readable
source report against the previously published archive. Eligible
submissions from enrolled owners merge automatically once the required
checks pass; control-plane changes (workflows, ownership, configuration)
always take the human review path and cannot be bundled with archives.

Antivirus and malware analysis are deferred and reported as
`NOT IMPLEMENTED / NOT SCANNED`; admission establishes publisher
authorization and package integrity only. `cargo-audit` dependency
advisory results from each archive's own `Cargo.lock` are reported
alongside, without gating admission.

See <https://phoxal.com> for public Phoxal documentation.
