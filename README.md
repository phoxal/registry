# phoxal/registry

Read-only Cargo registry for official executable packages from the Phoxal
Framework train. Framework libraries remain on crates.io.

- Cargo index: `sparse+https://phoxal.github.io/registry/`
- Package browser: <https://phoxal.github.io/registry/>

Reads are anonymous. Robot projects do not configure this registry directly;
the `phoxal` CLI uses it when resolving official packages.

Publication is owned by the framework release workflow. Published versions and
index entries are append-only, so changes here must add new release artifacts
rather than replace existing ones.

See <https://phoxal.com> for public Phoxal documentation.
