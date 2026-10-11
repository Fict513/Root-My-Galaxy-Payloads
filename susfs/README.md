# susfs

The hiding module this repository serves - **one build per variant per KMI** - and the loader that
puts it in.

Nothing here is committed by hand: this directory is written by the `SUSFS LKM` workflow
(`../.github/workflows/susfs-lkm.yml`) when it is dispatched with `publish`, together with
`../support/susfs-v1.json`, which is the file a client reads.

```
susfs/
  susfs_insmod                      the loader, shared by all three variants
  stable/susfs_guard_lkm-<kmi>.ko   upstream `main`   - six KMIs
  preview/susfs_guard_lkm-<kmi>.ko  upstream `dev`    - all eight, the only line that builds 6.12/6.18
  legacy/susfs_guard_lkm-<kmi>.ko   upstream `legacy` - six KMIs, no release string of its own
```

## The three variants

Upstream keeps more than one implementation line and they are not interchangeable, so each is built
from its own pinned commit - recorded per variant in the feed's `source.ref` - and published on its
own. Which one a device should load is not a decision this repository makes for it.

The KMI sets differ for a measured reason: the stable and legacy sources do not compile against 6.12
(`sus_mount.c` fails on `struct mnt_namespace`, which has no `ns_lock` and no `list` there, and
`MNT_CURSOR` is gone), so an Android 16 or 17 device has exactly one variant to load.

A variant is **not** a flavour. One module serves KernelSU, KernelSU-Next and ReSukiSU alike; what
differs is which implementation of susfs the phone loads.

## Provenance

Built from [inforcqb/susfs4ksu-lkm](https://github.com/inforcqb/susfs4ksu-lkm) at the commit each
variant's entry names, with its `kernel/` sources taken unmodified. The two variants that carry a
release string answer with `2.3.0-gki`, which they print when they load and which the build asserts
rather than assumes; the legacy line carries none, and its entry records `null` instead of a version
nobody can check.

That project ports susfs4ksu's feature logic and hook points together with SukiSU-Ultra's
`patch_memory`, `lsm_hook` and `symbol_resolver`. The loader is upstream's, published here unchanged
and pinned by digest.

## Licence

GPL-2.0-only, as the upstream sources are. The rest of this repository is Apache-2.0 (`../LICENSE`);
this directory is not, and the artifacts served from it stay under GPL-2.0-only. Serving a prebuilt GPL
module means the corresponding source has to be reachable, which is why every variant's entry names the
repository and the commit it was built from rather than only a version string.

## What loads it, and what does not

Nothing in this repository loads these files - a run has to decide to. On the devices this project
serves the loader is what makes a per-KMI module usable at all (see the workflow's header: a mismatched
`vermagic` is refused, and the loader fixes that up only when the kernel asks), and it needs root,
because it calls `init_module(2)` and reads addresses out of `/proc/kallsyms`.

Loading a module that patches kernel text and installs LSM hooks is privileged kernel code execution on
a stock kernel. A phone that loads one of these and does not come back needs its existing recovery path,
and none of this should be enabled before that path is known to work.
