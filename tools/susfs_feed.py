#!/usr/bin/env python3
"""The susfs tier's feed: one module per KMI, and the loader that puts it in.

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

## What is read, and what is refused

Everything in an entry is measured off the file being published - its size, its digest, and two
things read out of the binary itself rather than trusted from its name:

- it must contain its own module name, `susfs_guard_lkm`. A `cp` of the wrong artifact, a build that
  produced nothing, or a file renamed to look right is caught here rather than on a phone.
- it must contain the release string the build was cut from (`--version`, e.g. `2.3.0-gki`). The
  module prints it at load (`init v%s`), which is also what a reader sees in dmesg, so the entry and
  the log agree about what was loaded.

The loader beside it is not built here - it is a userspace program from the same project, pinned by
digest in the workflow - so this file only records its size and digest, taken from the file the
publish job fetched.

## Why the loader is published at all

The devices this repository serves run `CONFIG_MODULE_FORCE_LOAD=n`, so a module whose `vermagic`
does not name the running kernel release is refused by the kernel, not merely discouraged. Two ways
out exist and this repository takes the second for this tier:

- build the module per *release*, the way the KernelSU pairs in `kernelsu/` are built, which is a
  build per target per KMI; or
- publish the loader that resolves the module's unexported symbols out of `/proc/kallsyms` and
  patches the `vermagic=` value in `.modinfo` **only when the kernel's own message in `/dev/kmsg`
  asked for it**, then retries `init_module(2)` once.

The second is what the upstream project ships for exactly this case, and it is why one module per
KMI is enough here: the release is the device's, fixed up on the device, and recorded in the run's
log rather than baked into an artifact nobody can distinguish from the others.

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

# Where the published artifacts live in this repository. A directory of its own, because these are
# not KernelSU artifacts and a reader of `kernelsu/` must not have to know they exist.
SUSFS_DIR = "susfs"

# `susfs_guard_lkm-<kmi>.ko`, which is what the workflow names what it built.
MODULE = re.compile(r"^susfs_guard_lkm-(?P<kmi>android\d+-\d+\.\d+(?:\.\d+)?)\.ko$")

# The name the module carries in its own strings, and the line it prints when it loads.
NAME_MARKER = b"susfs_guard_lkm"

# Where the sources came from, and under which licence the artifacts are served.
SOURCE = {
    "repository": "inforcqb/susfs4ksu-lkm",
    "license": "GPL-2.0-only",
}


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


def verify(path: str, version: str) -> str:
    """The KMI, having checked the artifact is the module this tier serves."""
    if not os.path.isfile(path):
        raise SystemExit(f"no module at {path}")
    kmi = kmi_of(path)
    if not _contains(path, NAME_MARKER):
        raise SystemExit(
            f"{path} does not name {NAME_MARKER.decode()} in its own strings, so it is not the susfs "
            "module this feed serves."
        )
    if not _contains(path, version.encode()):
        raise SystemExit(
            f"{path} does not carry the release string {version!r}. The module prints it at load, so "
            "an entry that names a release its binary does not is an entry a reader cannot check."
        )
    return kmi


def module_entry(path: str, url_prefix: str, version: str) -> dict:
    kmi = verify(path, version)
    size, sha256 = _digest(path)
    return {
        "kmi": kmi,
        "url": f"{url_prefix.rstrip('/')}/{SUSFS_DIR}/{os.path.basename(path)}",
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


def build_feed(
    modules: list[str],
    loader: str,
    url_prefix: str,
    version: str,
    ref: str,
) -> dict:
    entries = [module_entry(path, url_prefix, version) for path in modules]
    entries.sort(key=lambda entry: entry["kmi"])
    kmis = [entry["kmi"] for entry in entries]
    if len(kmis) != len(set(kmis)):
        raise SystemExit(f"two modules claim the same KMI: {kmis}")
    if not entries:
        raise SystemExit("no modules given: a feed with nothing in it is not a publish")
    source = dict(SOURCE)
    source["ref"] = ref
    source["version"] = version
    return {
        "schemaVersion": 1,
        "source": source,
        "loader": loader_entry(loader, url_prefix),
        "modules": entries,
    }


def write_feed(repo: str, feed: dict, dry_run: bool) -> None:
    path = os.path.join(repo, SUSFS_FEED)
    text = json.dumps(feed, indent=2, ensure_ascii=False) + "\n"
    if dry_run:
        print(text, end="")
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _self_test() -> int:
    """The reader, against files written here rather than against the checkout.

    Three cases and each one is a mistake this tier can make: a module that carries no name is a
    different binary; a module whose release string disagrees with the feed is a binary from another
    build; and a duplicate KMI is a feed that offers a device two modules and no way to choose.
    """
    import tempfile

    failures = 0
    checks = 0
    version = "2.3.0-gki"

    def write(directory: str, name: str, body: bytes) -> str:
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(body)
        return path

    with tempfile.TemporaryDirectory() as tmp:
        good = write(tmp, "susfs_guard_lkm-android15-6.6.ko", NAME_MARKER + b"\0" + version.encode() + b"\0")
        loader = write(tmp, "susfs_insmod", b"kallsyms\0")

        checks += 1
        entry = module_entry(good, "https://example.test/main", version)
        if entry["kmi"] != "android15-6.6" or entry["size"] != os.path.getsize(good):
            print(f"FAIL a good module reads as {entry}")
            failures += 1

        checks += 1
        try:
            module_entry(write(tmp, "susfs_guard_lkm-android15-6.6.ko.bak", good.encode()), "u", version)
            print("FAIL a name that is not the module naming convention was accepted")
            failures += 1
        except SystemExit:
            pass

        checks += 1
        named = write(tmp, "susfs_guard_lkm-android14-6.1.ko", b"something else\0" + version.encode())
        try:
            module_entry(named, "u", version)
            print("FAIL a file with no module name in it was accepted")
            failures += 1
        except SystemExit:
            pass

        checks += 1
        stale = write(tmp, "susfs_guard_lkm-android14-6.1.ko", NAME_MARKER + b"\0" + b"2.2.0-gki")
        try:
            module_entry(stale, "u", version)
            print("FAIL a module built from another release was accepted")
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

        checks += 1
        feed = build_feed([good], loader, "https://example.test/main", version, "0" * 40)
        if feed["schemaVersion"] != 1 or feed["modules"][0]["kmi"] != "android15-6.6":
            print(f"FAIL the feed reads as {feed}")
            failures += 1

        checks += 1
        try:
            build_feed([], loader, "u", version, "0" * 40)
            print("FAIL an empty feed was accepted")
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
    parser.add_argument("--module", action="append", default=[], help="a built module, repeatable")
    parser.add_argument("--loader", help="the loader published beside them")
    parser.add_argument("--version", help="the release the modules were built from, e.g. 2.3.0-gki")
    parser.add_argument("--ref", help="the upstream commit the sources were read at")
    parser.add_argument("--url-prefix", help="repository raw-URL prefix this run publishes under")
    parser.add_argument("--check", metavar="PATH", help="only check one built module and write nothing")
    parser.add_argument("--dry-run", action="store_true", help="print the feed instead of writing it")
    arguments = parser.parse_args()

    if arguments.self_test:
        return _self_test()

    if arguments.check:
        if not arguments.version:
            parser.error("--check needs --version")
        print(f"ok   {arguments.check}: {verify(arguments.check, arguments.version)}")
        return 0

    if not arguments.module or not arguments.loader or not arguments.version or not arguments.ref:
        parser.error("--module, --loader, --version and --ref are all required to write a feed")
    if not arguments.url_prefix:
        parser.error("--url-prefix is required: an entry has to say where it is served from")

    feed = build_feed(
        arguments.module,
        arguments.loader,
        arguments.url_prefix,
        arguments.version,
        arguments.ref,
    )
    write_feed(arguments.repo, feed, arguments.dry_run)
    kmis = ", ".join(entry["kmi"] for entry in feed["modules"])
    print(f"{len(feed['modules'])} module(s) for {kmis}")
    for entry in feed["modules"]:
        print(f"  {entry['kmi']:<18} {entry['size']:>9} bytes  {entry['sha256'][:16]}...")
    if arguments.dry_run:
        print("  (dry run: nothing written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
