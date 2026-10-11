# susfs

The hiding module this repository serves, one build per KMI, and the loader that puts it in.

Nothing here is committed by hand: `susfs/` is written by the `SUSFS LKM` workflow
(`../.github/workflows/susfs-lkm.yml`) when it is dispatched with `publish`, together with
`../support/susfs-v1.json`, which is the file a client reads.

## Provenance

Built from [inforcqb/susfs4ksu-lkm](https://github.com/inforcqb/susfs4ksu-lkm) at the commit recorded
in the feed's `source.ref`, with its `kernel/` sources taken unmodified. The module answers with the
release string in `source.version` (`2.3.0-gki`), which it prints when it loads and which the build
asserts rather than assumes.

That project ports susfs4ksu's feature logic and hook points together with SukiSU-Ultra's
`patch_memory`, `lsm_hook` and `symbol_resolver`. The loader is upstream's, published here unchanged
and pinned by digest.

## Licence

GPL-2.0-only, as the upstream sources are. The rest of this repository is Apache-2.0 (`../LICENSE`);
this directory is not, and the artifacts served from it stay under GPL-2.0-only. Serving a prebuilt GPL
module means the corresponding source has to be reachable, which is why the feed's `source` field names
the repository and the commit it was built from rather than only a version string.

## What loads it, and what does not

Nothing in this repository loads these files - a run has to decide to. On the devices this project
serves the loader is what makes a per-KMI module usable at all (see the workflow's header: a mismatched
`vermagic` is refused, and the loader fixes that up only when the kernel asks), and it needs root,
because it calls `init_module(2)` and reads addresses out of `/proc/kallsyms`.

Loading a module that patches kernel text and installs LSM hooks is privileged kernel code execution on
a stock kernel. A phone that loads one of these and does not come back needs its existing recovery path,
and none of this should be enabled before that path is known to work.
