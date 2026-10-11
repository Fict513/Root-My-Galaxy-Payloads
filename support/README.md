# Support feed schema

`targets-v3.json` keeps one entry for each shared exploit and KernelSU payload.
Automatic selection matches the exact device model and three-part kernel
version, such as `6.6.98`.

Each entry contains only:

- `payloadId` and `displayName`;
- one or more exact `Build.MODEL` values in `models`;
- one or more versions in `kernelVersions`;
- `url` and `size` for the exploit and KernelSU artifacts.

A `sha256` may also be declared on an artifact, which the client verifies in place of the size.
Pairs rebuilt by CI declare one, because the build computes the digest of what it just produced;
entries written before that was the case carry only a size, which the client still checks.

The `kernelsu` artifact may also declare `version`: the KernelSU release the daemon beside it was
built from, such as `3.4.0`. A pair rebuilt by CI declares one, taken from the tag the run built at
(`tools/update_feed.py --version`), and `tools/update_feed.py --backfill` writes it for entries whose
`payloadId` already carries a version and which are not being rebuilt. The app uses it to offer the
manager of the KernelSU a run will actually stage - the daemon and the manager have to be the same
release - and falls back to the flavour's own release for an entry that declares none.

An entry may also declare `flavor`: which project's KernelSU its `kernelsu` artifact is, one of
`kernelsu`, `kernelsu-next` or `resukisu`. The app compares it against the three projects it knows
and offers that flavour's manager; an entry that declares none is the plain `kernelsu` one, which is
what every entry written before flavours existed is. One device can be served by several flavours at
once - the app shows them as a row of chips to choose between - so the two entries differ in this
field and in the artifact they name, and nothing else. `tools/update_feed.py --create` writes one
beside an entry that already serves the device, which is how a second flavour reaches a target that
has only ever been served the first.

An entry may additionally set `requiresFreshP0Session` to `true` when slide
discovery and exploitation must run in the same payload process. The app then
disables its per-boot P0 cache for that profile and gives the single combined
attempt the target-specific long timeout. The field defaults to `false`, so
existing profiles retain the cached multi-attempt behavior.

The app extracts the leading numeric version from `uname -r`. Kernel suffixes,
Android build displays, fingerprints, and security-patch dates do not
participate in matching.

`targets-v2.json` remains unchanged for released 0.2.3 clients. New clients
read only schema version 3.

## The generic tier

`kernelsu-generic.json` is a second, separate feed, and it is read only when a device has no entry of
its own to be served by. It holds one daemon per flavour, each carrying a kernel module for several
KMIs instead of one:

```json
{
  "schemaVersion": 1,
  "generic": [
    {
      "flavor": "kernelsu",
      "kmis": ["android12-5.10", "android14-6.1", "android15-6.6"],
      "daemon": { "url": "...", "size": 6407096, "sha256": "...", "version": "3.3.0" }
    }
  ]
}
```

The `kmis` array is read out of the daemon's own asset table rather than typed in, and the entry is
refused if it disagrees with the binary - a daemon that claims a KMI it has no module for is one that
would fail on the phone with nothing in the feed to say so.

Why it is a separate file and not a field in `targets-v3.json`: an entry there names the artifact its
device was tested with, and that file is rewritten in place by span edits for every pair a release
moves. A generic daemon is a fallback for devices that have no such entry, so it lives where a
mistake can only offer a fallback that does not load, and cannot move a device that works onto a
different daemon. Nothing in this file is served by any entry in `targets-v3.json`, and no job writes
both.

The tier exists because the KernelSU half of a payload is the one half that is not device-specific:
`ksud` picks its module out of its own asset directory by KMI at run time, so a daemon carrying one
module per KMI serves a whole KMI family. It replaces the older arrangement where a single artifact
was shared by several device entries - the `s25u` bundle and its siblings - because those were built
outside the pair job and could not be rebuilt when a KernelSU release moved.

## The susfs tier

`susfs-v1.json` is a third, separate feed, and the only one that serves something which is not a
KernelSU artifact. It holds one hiding module per KMI **per variant**, plus the loader that puts them
in:

```json
{
  "schemaVersion": 1,
  "loader": { "url": ".../susfs/susfs_insmod", "size": 32800, "sha256": "..." },
  "variants": [
    {
      "id": "stable",
      "source": {
        "repository": "inforcqb/susfs4ksu-lkm",
        "license": "GPL-2.0-only",
        "ref": "191339da5db5e9a45a4b011f9f7aa4174a760bae",
        "version": "2.3.0-gki"
      },
      "modules": [
        {
          "kmi": "android15-6.6",
          "url": ".../susfs/stable/susfs_guard_lkm-android15-6.6.ko",
          "size": 374224,
          "sha256": "..."
        }
      ]
    }
  ]
}
```

**Three variants, because upstream keeps three lines and they are not interchangeable.** Each is
built from its own pinned commit, published under `susfs/<variant>/`, and carries its pin in its own
entry:

| variant | upstream line | KMIs | notes |
| --- | --- | --- | --- |
| `stable` | `main` | the six below 6.12 | the line upstream ships as a release |
| `preview` | `dev` | all eight | the only line whose sources compile against 6.12/6.18 |
| `legacy` | `legacy` | the six below 6.12 | the older line; carries no release string, so its `version` is `null` |

Those KMI sets are not a preference. The stable and legacy sources fail to build against 6.12 (ten
errors in `sus_mount.c`: `struct mnt_namespace` has no `ns_lock` and no `list`, and `MNT_CURSOR` is
gone), which is why upstream's own stable workflow refuses to add those two KMIs - so a device on
Android 16 or 17 has exactly one variant to load. A variant is not a flavour: one module serves
KernelSU, KernelSU-Next and ReSukiSU alike, and nothing in this feed chooses between the variants for
a device.

Why a third file: susfs is not in the KernelSU module this repository publishes - a built
`kernelsu-next-*.ko` has no `susfs` string in it at all - so on these devices it can only arrive as a
second module, built by `.github/workflows/susfs-lkm.yml` from those pinned commits. No device is
named in an entry, because the module is not built for one: one binary per KMI serves every device in
that family. It is versioned apart from the KernelSU payloads so that a susfs release does not look
like a payload that moved for devices which never load it, and a KernelSU publish never rebuilds a
module that did not change.

Every field is measured off the file being published, and two are read out of the binary rather than
trusted from its name: the module has to contain `susfs_guard_lkm`, and the release string when its
variant declares one - `tools/susfs_feed.py` refuses the entry otherwise, and refuses a variant that
built nothing at all. The `kmis` of the generic tier have a sibling here: the KMI in the artifact's
name is read off the file's own name, and two modules claiming one KMI is a feed that offers a device
two binaries and no way to choose.

The loader is published beside the modules and is not built here, and it serves all three variants:
upstream ships the same bytes in its stable and preview releases, which is the digest pinned in the
workflow. These devices run `CONFIG_MODULE_FORCE_LOAD=n`, so a module whose `vermagic` does not name
the running release is refused by the kernel rather than merely discouraged; the loader resolves the
module's unexported symbols out of `/proc/kallsyms` and patches `vermagic=` in `.modinfo` only after
the kernel's own message in `/dev/kmsg` asked for it, then retries `init_module(2)` once. That is what
keeps one module per KMI per variant instead of one per release per KMI and per variant. Both files
need root to load, and neither is loaded by any job in this repository: the workflow builds, checks
and publishes, and a person decides what a device runs.

## How entries are published

A KernelSU release makes every pair in this file stale, and `upstream-watch.yml` is what closes
that gap: it rebases the Samsung patch onto the new tag, builds a pair for each target the feed
serves, and commits the artifacts with the entry that points at them. The targets and the release
each pair is built for are derived by [`../tools/pairs.py`](../tools/pairs.py) from this file and
the artifacts already in [`../kernelsu/`](../kernelsu/) - a release is read out of the `vermagic`
of the module being replaced, so a rebuild claims exactly what the module users are running
claims, and nothing has to be typed in by hand.

A pair has two KMI names and they are not interchangeable. The artifact keeps the name the device's
modules already use, which for the 5.15 ports carries the kernel release (`android13-5.15.189`),
while the DDK publishes its images per family (`android13-5.15`) and never per release. Both are
derived from the same module name and passed on separately, and `ksu-build.yml` checks its image
exists before pulling it - a job's container is created before any of its steps run, so a tag that
was never published is otherwise a failed job about a missing manifest rather than about the KMI.

What that leaves for a person, and why:

- **A rebase that conflicts.** A KernelSU release that rewrites the code the Samsung delta
touches cannot be merged by a runner. The workflow tries, and files an issue with the conflicting
hunks when it cannot.
- **Entries served by a hand-built pair.** The `s25u` bundle and its siblings are one module
  shared by several models, built outside the pair job. `tools/pairs.py` reports them instead of
  guessing, and the run summary lists them. A rebuilt daemon of that shape belongs in
  `kernelsu-generic.json` rather than shared between entries - see
  [the generic tier](#the-generic-tier) - because a daemon the workflow builds is one a release can
  move.
- **A device port with no document.** The release a pair must claim is device truth; where it has
never been written down there is nothing to build against.
