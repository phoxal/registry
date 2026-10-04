# Historical Phoxal registry

This repository retains the previously published sparse index, package archives, and publication provenance.
It is retired from active Phoxal distribution and accepts no new package submissions.
Existing archives and checksums remain available; their history is not reset or deleted.

New Rust library and application releases use crates.io and standard release-plz workflows in their owning repositories.
Participant sources in robot projects use local paths or pinned Git revisions, including passive model assets that need no artificial Cargo package.
The former `cargo phoxal publish`, registry admission, and automatic submission merge workflow are removed.

See the [framework](https://github.com/phoxal/framework), [developer tool](https://github.com/phoxal/cargo), and [simulator](https://github.com/phoxal/simulator) for current installation and release instructions.
