#!/usr/bin/env python3
"""The susfs tier's feed: one module per KMI, per variant, and the loader that puts it in.

SUSFS is a hiding patch-set, normally carried inside the KernelSU kernel module. This repository
ships its own KernelSU module per target, and that module has no susfs in it - so on these devices
susfs has to arrive as a *second* module, built per KMI, loaded next to the KernelSU one.

That is why this feed is a file of its own rather than rows in `targets-v3.json` or
`kernelsu-generic.json`:

- it is not a device entry. No device is named in it, because the module is not built for one:
  `susfs_guard_lkm` is one binary per KMI and serves every device whose kernel is in that family.
- it is not the KernelSU half either. The daemon in `kernelsu-generic.json` carries *their* module;
  this carries a different module from a different project, under a different licence, and a client
  that never asks for it must not be affected by a change in it.
- it is versioned apart on purpose. A new susfs release is not a new KernelSU release, and coupling
  the two would make every KernelSU publish rebuild a module that did not change - and every susfs
  publish look like a payload that moved for devices that never load it.

## Variants, and why the tier publishes three of them

Upstream keeps more than one implementation line, and they are not interchangeable:

- **stable** (`main`): the line upstream calls stable, and the only one whose own workflow ships as
  a release. Six KMIs: 5.10 ×2, 5.15 ×2, 6.1, 6.6.
- **preview** (`dev`): the line that carries the 6.12/6.18 LSM path. Lookup there is one static call
  per hook and LSM slot instead of the hlist `security_hook_heads` was, which is a different
  mechanism with its own code path - so on a 6.12 or 6.18 device this is the variant that exists,
  and it is built for all eight KMIs rather than six.
- **legacy**: the older line, kept by upstream for the range it was written for, with no version
  string of its own in `kernel/susfs.h`. It is published because a phone that misbehaves on the
  current line has one other thing to try, and a variant that is not built is not one.
- **samsung**: upstream's stable sources with this repository's LSM install path in place of theirs -
  a kretprobe on the SELinux implementation of each hook instead of a write into
  `security_hook_heads`, which Samsung's kernel refuses with `-EFAULT` (measured on an SM-S938U1).
  Built for the DirtyFrag method, and the only line expected to arm on a stock Samsung kernel.

A variant is not a flavour: the same module serves KernelSU, KernelSU-Next and ReSukiSU alike. What
differs between variants is which implementation of susfs a device loads, so each is published on its
own (`susfs/<variant>/...`), carries its own source pin, and appears as its own entry in the feed.
Nothing here decides which one a device should use.

## What is read, and what is refused

Everything in an entry is measured off the file being published - its size, its digest, and two
things read out of the binary itself rather than trusted from its name:

- it must contain its own module name, `susfs_guard_lkm`. A `cp` of the wrong artifact, a build that
  produced nothing, or a file renamed to look right is caught here rather than on a phone.
- when the variant declares a release string, the binary must carry it. The module prints it at load
  (`init v%s`), which is also what a reader sees in dmesg, so the entry and the log agree about what
  was loaded. The legacy line has no such string, and its variant records `null` rather than a
  version nobody can check.

The loader beside them is not built here - it is a userspace program from the same project, pinned by
digest in the workflow - so this file only records its size and digest, taken from the file the
publish job fetched. One loader serves every variant: upstream ships the same bytes for its stable
and preview releases, verified by digest, and a variant that later needs a different one is a
variant this feed can grow a loader field for.

## Why the loader is published at all

The devices this repository serves run `CONFIG_MODULE_FORCE_LOAD=n`, so a module whose `vermagic`
does not name the running kernel release is refused by the kernel, not merely discouraged. Two ways
out exist and this repository takes the second for this tier:

- build the module per *release*, the way the KernelSU pairs in `kernelsu/` are built, which is a
  build per target per KMI per variant; or
- publish the loader that resolves the module's unexported symbols out of `/proc/kallsyms` and
  patches the `vermagic=` value in `.modinfo` **only when the kernel's own message in `/dev/kmsg`
  asked for it**, then retries `init_module(2)` once.

The second is what the upstream project ships for exactly this case, and it is why one module per
KMI per variant is enough here: the release is the device's, fixed up on the device, and recorded in
the run's log rather than baked into an artifact nobody can distinguish from the others.

The loader is *not* a replacement for the app's own privilege: it needs to be run as root, because
`init_module(2)` and a readable `/proc/kallsyms` both need it. Nothing about it is device-specific.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

# The file the tier is served from. One name, and no other tool writes it.
SUSFS_FEED = "support/susfs-v1.json"

# Where the published artifacts live in this repository. A directory of its own, with a directory per
# variant under it, because these are not KernelSU artifacts and a reader of `kernelsu/` must not
# have to know they exist.
SUSFS_DIR = "susfs"

# `susfs_guard_lkm-<kmi>.ko`, which is what the workflow names what it built.
MODULE = re.compile(r"^susfs_guard_lkm-(?P<kmi>android\d+-\d+\.\d+(?:\.\d+)?)\.ko$")

# The name the module carries in its own strings, and the line it prints when it loads.
NAME_MARKER = b"susfs_guard_lkm"

# Where the sources came from, and under which licence the artifacts are served.
SOURCE_REPOSITORY = "inforcqb/susfs4ksu-lkm"
SOURCE_LICENSE = "GPL-2.0-only"

# The variants this tier serves, and which upstream branch each is. A variant's own release string is
# *not* here: it comes from the manifest the run writes, because it is a property of the commit that
# was built rather than of the branch.
# `samsung` is upstream's stable sources with this repository's kretprobe install path in place of
# theirs - the one line built for the DirtyFrag method, and the one expected to arm on a stock Samsung
# kernel. See `../susfs-lkm/lsm_hook.c` for why the upstream install path cannot.
VARIANTS = ("stable", "preview", "legacy", "samsung")


def _digest(path: str) -> tuple[int, str]:
    size = os.path.getsize(path)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return size, digest.hexdigest()


def _contains(path: str, needle: bytes) -> bool:
    with open(path, "rb") as handle:
        return needle in handle.read()


def kmi_of(path: str) -> str:
    """The KMI a built module claims to be for. Refuses rather than guessing."""
    name = os.path.basename(path)
    found = MODULE.match(name)
    if not found:
        raise SystemExit(
            f"{name} is not named susfs_guard_lkm-<kmi>.ko, so the KMI it was built for cannot be "
            "read off it. A module served under the wrong KMI is one a device loads for the wrong "
            "kernel family."
        )
    return found.group("kmi")


def verify(path: str, version: str | None) -> str:
    """The KMI, having checked the artifact is the module this variant serves."""
    if not os.path.isfile(path):
        raise SystemExit(f"no module at {path}")
    kmi = kmi_of(path)
    if not _contains(path, NAME_MARKER):
        raise SystemExit(
            f"{path} does not name {NAME_MARKER.decode()} in its own strings, so it is not the susfs "
            "module this feed serves."
        )
    if version is not None and not _contains(path, version.encode()):
        raise SystemExit(
            f"{path} does not carry the release string {version!r}. The module prints it at load, so "
            "an entry that names a release its binary does not is an entry a reader cannot check."
        )
    return kmi


def module_entry(path: str, variant: str, url_prefix: str, version: str | None) -> dict:
    kmi = verify(path, version)
    size, sha256 = _digest(path)
    return {
        "kmi": kmi,
        "url": f"{url_prefix.rstrip('/')}/{SUSFS_DIR}/{variant}/{os.path.basename(path)}",
        "size": size,
        "sha256": sha256,
    }


def loader_entry(path: str, url_prefix: str) -> dict:
    if not os.path.isfile(path):
        raise SystemExit(f"no loader at {path}")
    if not _contains(path, b"kallsyms"):
        raise SystemExit(
            f"{path} does not mention kallsyms, so it is not the loader this tier publishes: the "
            "module's unexported symbols are what it exists to resolve."
        )
    size, sha256 = _digest(path)
    return {
        "url": f"{url_prefix.rstrip('/')}/{SUSFS_DIR}/{os.path.basename(path)}",
        "size": size,
        "sha256": sha256,
    }


def read_manifest(path: str) -> list[dict]:
    """The run's own account of what it built: one record per variant.

    Written by the publish job rather than derived from the artifacts, because a file name cannot say
    which commit a module came from - and a feed that guessed the pin would attribute one line's
    module to another's.
    """
    with open(path, encoding="utf-8") as handle:
        records = json.load(handle)
    if not isinstance(records, list) or not records:
        raise SystemExit(f"{path} is not a non-empty list of variants")
    seen = set()
    for record in records:
        variant = record.get("variant")
        if variant not in VARIANTS:
            raise SystemExit(f"{path}: {variant!r} is not one of {', '.join(VARIANTS)}")
        if variant in seen:
            raise SystemExit(f"{path}: {variant} appears twice")
        seen.add(variant)
        if not record.get("ref"):
            raise SystemExit(f"{path}: variant {variant} names no ref, so its modules cannot be traced")
        if not record.get("modules"):
            raise SystemExit(f"{path}: variant {variant} built nothing, so it is not a variant to publish")
    return records


def build_feed(
    records: list[dict],
    loader: str,
    url_prefix: str,
    repository: str,
) -> dict:
    variants = []
    for record in sorted(records, key=lambda entry: VARIANTS.index(entry["variant"])):
        variant = record["variant"]
        version = record.get("version")
        entries = [
            module_entry(path, variant, url_prefix, version) for path in record["modules"]
        ]
        entries.sort(key=lambda entry: entry["kmi"])
        kmis = [entry["kmi"] for entry in entries]
        if len(kmis) != len(set(kmis)):
            raise SystemExit(f"{variant}: two modules claim the same KMI: {kmis}")
        variants.append(
            {
                "id": variant,
                "source": {
                    "repository": repository,
                    "license": SOURCE_LICENSE,
                    "ref": record["ref"],
                    "version": version,
                },
                "modules": entries,
            }
        )
    # And the one thing the whole file has to be able to say: which variants it serves, in the order
    # they are built for. A variant that disappears silently is how a device keeps loading a module
    # nobody publishes any more.
    return {"schemaVersion": 1, "loader": loader_entry(loader, url_prefix), "variants": variants}


def write_feed(repo: str, feed: dict, dry_run: bool) -> None:
    path = os.path.join(repo, SUSFS_FEED)
    text = json.dumps(feed, indent=2, ensure_ascii=False) + "\n"
    if dry_run:
        print(text, end="")
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def coverage(feed: dict) -> tuple[list[str], list[tuple[str, str]]]:
    """The KMIs every variant serves, and the pairs a variant is missing.

    What a publish owes a reader is not every pair - the eight-KMI line and the six-KMI line are
    different lines, and the legacy line may not build the newest ones at all. What it owes is the
    truth about which pairs exist, so a missing one is named rather than left to be noticed.
    """
    served = {entry["kmi"] for variant in feed["variants"] for entry in variant["modules"]}
    missing = [
        (variant["id"], kmi)
        for variant in feed["variants"]
        for kmi in sorted(served)
        if kmi not in {entry["kmi"] for entry in variant["modules"]}
    ]
    return sorted(served), missing


def _self_test() -> int:
    """The reader, against files written here rather than against the checkout.

    Every case below is a mistake this tier can make: a module that carries no name is a different
    binary; a module whose release string disagrees with the feed is a binary from another build; a
    duplicate KMI is a feed that offers a device two modules and no way to choose; and a variant with
    nothing in it is one a reader would take for a line that exists.
    """
    import tempfile

    failures = 0
    checks = 0
    version = "2.3.0-gki"

    def write(directory: str, name: str, body: bytes) -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(body)
        return path

    with tempfile.TemporaryDirectory() as tmp:
        stable = os.path.join(tmp, "stable")
        good = write(
            stable,
            "susfs_guard_lkm-android15-6.6.ko",
            NAME_MARKER + b"\0" + version.encode() + b"\0",
        )
        legacy = write(
            os.path.join(tmp, "legacy"),
            "susfs_guard_lkm-android15-6.6.ko",
            NAME_MARKER + b"\0no version here\0",
        )
        loader = write(tmp, "susfs_insmod", b"kallsyms\0")

        checks += 1
        entry = module_entry(good, "stable", "https://example.test/main", version)
        if entry["kmi"] != "android15-6.6" or "/stable/" not in entry["url"]:
            print(f"FAIL a good module reads as {entry}")
            failures += 1

        checks += 1
        if verify(legacy, None) != "android15-6.6":
            print("FAIL a variant with no release string was refused")
            failures += 1

        checks += 1
        try:
            module_entry(write(stable, "susfs_guard_lkm-android15-6.6.ko.bak", good.encode()), "stable", "u", version)
            print("FAIL a name that is not the module naming convention was accepted")
            failures += 1
        except SystemExit:
            pass

        checks += 1
        named = write(stable, "susfs_guard_lkm-android14-6.1.ko", b"something else\0" + version.encode())
        try:
            module_entry(named, "stable", "u", version)
            print("FAIL a file with no module name in it was accepted")
            failures += 1
        except SystemExit:
            pass

        checks += 1
        try:
            module_entry(legacy, "legacy", "u", version)
            print("FAIL a module built from another release was accepted for a variant that names one")
            failures += 1
        except SystemExit:
            pass

        checks += 1
        try:
            loader_entry(write(tmp, "other", b"nothing here"), "u")
            print("FAIL a file that is not the loader was accepted")
            failures += 1
        except SystemExit:
            pass

        records = [
            {"variant": "stable", "ref": "a" * 40, "version": version, "modules": [good]},
            {"variant": "legacy", "ref": "b" * 40, "version": None, "modules": [legacy]},
        ]
        checks += 1
        feed = build_feed(records, loader, "https://example.test/main", SOURCE_REPOSITORY)
        if [variant["id"] for variant in feed["variants"]] != ["stable", "legacy"]:
            print(f"FAIL the feed's variants read as {[v['id'] for v in feed['variants']]}")
            failures += 1

        checks += 1
        served, missing = coverage(feed)
        if served != ["android15-6.6"] or missing != []:
            print(f"FAIL coverage reads served={served} missing={missing}")
            failures += 1

        checks += 1
        partial = build_feed(
            [
                {"variant": "stable", "ref": "a" * 40, "version": version, "modules": [good]},
                {
                    "variant": "legacy",
                    "ref": "b" * 40,
                    "version": None,
                    "modules": [write(os.path.join(tmp, "legacy"), "susfs_guard_lkm-android14-6.1.ko", NAME_MARKER)],
                },
            ],
            loader,
            "https://example.test/main",
            SOURCE_REPOSITORY,
        )
        _, missing = coverage(partial)
        # Variant-major, in the order the feed serves them: the report is read next to the variants it
        # is about, so it lists a variant's gaps together rather than interleaving the three lines.
        if missing != [("stable", "android14-6.1"), ("legacy", "android15-6.6")]:
            print(f"FAIL a gap between variants reads as {missing}")
            failures += 1

        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as handle:
            json.dump(records, handle)
        checks += 1
        if len(read_manifest(manifest)) != 2:
            print("FAIL a manifest of two variants did not read back as two")
            failures += 1

        for label, broken in (
            ("a variant with no modules", [{"variant": "stable", "ref": "a" * 40, "modules": []}]),
            ("a variant with no ref", [{"variant": "stable", "ref": "", "modules": [good]}]),
            ("an unknown variant", [{"variant": "friend", "ref": "a" * 40, "modules": [good]}]),
        ):
            checks += 1
            with open(manifest, "w", encoding="utf-8") as handle:
                json.dump(broken, handle)
            try:
                read_manifest(manifest)
                print(f"FAIL {label} was accepted")
                failures += 1
            except SystemExit:
                pass

    if failures:
        print(f"self-test: {failures} of {checks} check(s) failed")
        return 1
    print(f"self-test: {checks} check(s), no failure")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--self-test", action="store_true", help="run the reader's own cases and stop")
    parser.add_argument("--repo", default=".", help="payload repository root")
    parser.add_argument("--manifest", help="the run's account of what it built, one record per variant")
    parser.add_argument("--loader", help="the loader published beside the modules")
    parser.add_argument(
        "--repository",
        default=SOURCE_REPOSITORY,
        help="the upstream repository the variants' refs are in",
    )
    parser.add_argument("--url-prefix", help="repository raw-URL prefix this run publishes under")
    parser.add_argument("--dry-run", action="store_true", help="print the feed instead of writing it")
    parser.add_argument(
        "--check",
        nargs=2,
        metavar=("PATH", "VARIANT"),
        help="only check one built module against a variant, and write nothing",
    )
    parser.add_argument("--version", help="the release the checked module was built from, if it names one")
    arguments = parser.parse_args()

    if arguments.self_test:
        return _self_test()

    if arguments.check:
        path, variant = arguments.check
        if variant not in VARIANTS:
            parser.error(f"--check VARIANT must be one of {', '.join(VARIANTS)}")
        print(f"ok   {variant}: {verify(path, arguments.version)}")
        return 0

    if not arguments.manifest or not arguments.loader:
        parser.error("--manifest and --loader are both required to write a feed")
    if not arguments.url_prefix:
        parser.error("--url-prefix is required: an entry has to say where it is served from")

    feed = build_feed(
        read_manifest(arguments.manifest),
        arguments.loader,
        arguments.url_prefix,
        arguments.repository,
    )
    write_feed(arguments.repo, feed, arguments.dry_run)

    served, missing = coverage(feed)
    for variant in feed["variants"]:
        kmis = ", ".join(entry["kmi"] for entry in variant["modules"])
        print(f"{variant['id']:<8} {len(variant['modules'])} module(s): {kmis}")
        if variant["source"]["version"] is None:
            print(f"         no release string: built from {variant['source']['ref'][:12]}")
    if missing:
        print(f"not published ({len(missing)}): " + ", ".join(f"{v}/{k}" for v, k in missing))
    if arguments.dry_run:
        print("(dry run: nothing written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
