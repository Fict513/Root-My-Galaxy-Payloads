#!/usr/bin/env python3
r"""Wire SUSFS's try_umount into a merged KernelSU-Next + susfs tree.

Run by `.github/workflows/ksu-susfs.yml` after the merge step, never by hand: it edits files the
merge produced (the fork's `susfs_supercall.c` among them), so it has to run against a tree that
already has both halves.

Every edit asserts on its anchor and the script exits non-zero when one is missing.  That is the
whole point of doing this here rather than by hand: an edit that silently did nothing would produce a
daemon that builds, boots, reports nothing about try_umount and quietly keeps the KernelSU route -
which is exactly the state this change exists to leave.

What it does:

  1. `kernel/susfs/susfs_supercall.c`
     - includes the new layer's header;
     - carries the command's fifth argument through the transport (`struct susfs_tw`), which the
       try_umount command needs and no other command uses;
     - dispatches upstream's id (0x5555a) and our deprecated one (0x55580);
     - accepts both ids in `susfs_cmd_handled()`, without which the kprobe leaves the command to
       `reboot(2)` and the caller reads "the kernel never handled this command";
     - reports the feature, gated on the layer being active.
  2. `kernel/susfs/susfs_main.c`
     - registers the layer in `susfs_layers[]`, which is what makes its init run at all: without the
       entry the feature is never initialised and, because it is advertised only while its init
       succeeded, never reported - measured on the phone against the first published daemon;
  3. `kernel/hook/syscall_hook_manager.c`
     - calls `susfs_try_umount()` in KernelSU-Next's setuid work, immediately before
       `ksu_handle_setresuid()`, which is upstream's order ("susfs come first").
It touches no Kbuild on purpose: the workflow's object list is built from the sources it finds
(`objects=$(cd KernelSU/kernel && ls susfs/*.c | sed 's/\.c$/.o/')`), so a new file in that
directory is compiled without an edit here - and adding one would list the same object twice.
"""

import pathlib
import re
import sys

SUSFS_DIR = pathlib.Path("KernelSU/kernel/susfs")
SUPERCALL = SUSFS_DIR / "susfs_supercall.c"
SETUID = pathlib.Path("KernelSU/kernel/hook/syscall_hook_manager.c")
LAYERS = SUSFS_DIR / "susfs_main.c"

changes = []


def report(path, what):
    changes.append(f"{path}: {what}")
    print(f"  {path}: {what}")


def read(path):
    if not path.exists():
        sys.exit(f"wire_try_umount: {path} is missing - the merge step did not run?")
    # newline="" on both ends: an edit must not rewrite every line's ending, or a run on a machine
    # that is not Linux turns a three-line diff into a whole-file one (measured: Python's text mode
    # rewrote the fork's CRLF sources as CRLF throughout, and a LF source as CRLF).
    with open(path, "r", encoding="utf-8", newline="") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def insert_after(text, anchor, addition, path, what):
    """Insert `addition` after the line containing `anchor`, and insist the anchor was there."""
    idx = text.find(anchor)
    if idx < 0:
        sys.exit(f"wire_try_umount: anchor not found in {path}: {anchor!r}")
    end = text.find("\n", idx)
    if end < 0:
        sys.exit(f"wire_try_umount: anchor line is unterminated in {path}: {anchor!r}")
    report(path, what)
    return text[: end + 1] + addition + text[end + 1 :]


def insert_before(text, anchor, addition, path, what, indent_from=None):
    """Insert `addition` before the line containing `anchor`."""
    idx = text.find(anchor)
    if idx < 0:
        sys.exit(f"wire_try_umount: anchor not found in {path}: {anchor!r}")
    line_start = text.rfind("\n", 0, idx) + 1
    indent = ""
    if indent_from is not None:
        m = re.match(r"[ \t]*", text[line_start:])
        indent = m.group(0) if m else ""
    report(path, what)
    return text[:line_start] + indent + addition + "\n" + text[line_start:]


def insert_after_first_include(text, addition, path, what):
    """Insert `addition` after the file's first #include, whatever that include happens to be.

    Used for KernelSU's own files: their include lists are not this repository's to assume, and the
    first CI run made the point - an anchor on `#include <linux/cred.h>` failed because
    syscall_hook_manager.c does not include it at v3.4.1.
    """
    match = re.search(r"^[ \t]*#include[^\n]*\n", text, flags=re.M)
    if not match:
        sys.exit(f"wire_try_umount: no #include line in {path} to anchor the new include on")
    report(path, what)
    return text[: match.end()] + addition + text[match.end() :]


def already_wired(text):
    return "susfs_try_umount" in text


def wire_supercall():
    text = read(SUPERCALL)
    if already_wired(text):
        report(SUPERCALL, "already wired, leaving it alone")
        return

    # 1. the header, beside the layer's other includes.
    text = insert_after(
        text,
        '#include "susfs_log.h"',
        '#include "susfs_try_umount.h"\t/* CONFIG_KSU_SUSFS_TRY_UMOUNT (upstream\'s try_umount) */\n',
        SUPERCALL,
        "include the try_umount layer",
    )

    # 2. the fifth argument, carried through the transport.  Only this command uses it: upstream
    #    writes the error *there* for try_umount, because that struct has no err field of its own.
    text = insert_after(
        text,
        "void __user *payload;",
        "\t/* The command's fifth argument, which upstream's helper uses as the error pointer for\n"
        "\t * CMD_SUSFS_ADD_TRY_UMOUNT.  No other command here passes one. */\n"
        "\tvoid __user *err_ptr;\n",
        SUPERCALL,
        "carry the fifth argument in struct susfs_tw",
    )
    text = insert_after(
        text,
        "tw->payload = payload;",
        "\t/* x5, i.e. the argument after the payload.  Read only for the command whose caller\n"
        "\t * owns the contract for it - see the dispatch below, which passes NULL for any other. */\n"
        "\ttw->err_ptr = (void __user *)real_regs->regs[5];\n",
        SUPERCALL,
        "capture the fifth argument in reboot_pre",
    )

    # 3. the dispatch.  Upstream's id gets the error pointer; ours (deprecated) never does, so a
    #    caller that used it cannot have four bytes written into an address it never passed.
    dispatch = (
        "\tcase SUSFS_CMD_ADD_TRY_UMOUNT_UPSTREAM:\n"
        "\t\tsusfs_try_umount_supercall(&arg, tw->err_ptr);\n"
        "\t\tbreak;\n"
        "\tcase CMD_SUSFS_ADD_TRY_UMOUNT:\n"
        "\t\tsusfs_try_umount_supercall(&arg, NULL);\n"
        "\t\tbreak;\n"
    )
    text = insert_before(
        text,
        "case CMD_SUSFS_SET_UNAME:\n\t\tsusfs_uname_supercall(&arg);",
        dispatch.rstrip("\n"),
        SUPERCALL,
        "dispatch both try_umount ids in susfs_tw_func()",
    )

    # 4. the gate the kprobe consults before swallowing the syscall.  Anchored on the last case of
    #    that switch (the worker's own switch has no `return true;` arm, so this pair is unique).
    text = insert_before(
        text,
        "case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:\n\t\treturn true;",
        "\tcase SUSFS_CMD_ADD_TRY_UMOUNT_UPSTREAM:\n"
        "\tcase CMD_SUSFS_ADD_TRY_UMOUNT:",
        SUPERCALL,
        "accept both ids in susfs_cmd_handled()",
    )

    # 5. the feature list, which is what makes a module take the SUSFS route instead of ksud's
    #    umount list.  Gated on the layer being active: a tree where path_umount did not resolve
    #    must not advertise a feature it cannot perform.
    text = insert_after(
        text,
        '{ "CONFIG_KSU_SUSFS_SUS_MAP\\n",',
        '\t{ "CONFIG_KSU_SUSFS_TRY_UMOUNT\\n",\tsusfs_try_umount_active },\n',
        SUPERCALL,
        "report CONFIG_KSU_SUSFS_TRY_UMOUNT",
    )

    write(SUPERCALL, text)


def wire_layer():
    """Put the layer in the init table, without which nothing in it ever runs.

    This is the edit whose absence the phone found: the feature list reports an entry only while its
    `active` callback says so, and that callback answers from the state this init sets up - so a
    tree where the layer is never initialised reports the feature as absent, which is what it is.
    The first published daemon was exactly that: the command was reachable and the unmount was not.
    """
    text = read(LAYERS)
    if "susfs_try_umount_init" in text:
        report(LAYERS, "already wired, leaving it alone")
        return

    text = insert_after_first_include(
        text,
        '#include "susfs_try_umount.h"\t/* the layer below */\n',
        LAYERS,
        "include the try_umount layer",
    )

    # Non-fatal, and false for `armed`: the module works without it (the feature is simply not
    # advertised), so refusing to load over it would be a worse answer than degrading.
    text = insert_after(
        text,
        "susfs_hide_syms_exit,",
        '    { "try_umount",\tsusfs_try_umount_init,\t\tsusfs_try_umount_exit,\tfalse, false },\n',
        LAYERS,
        "register the layer in susfs_layers[]",
    )

    write(LAYERS, text)


def wire_setuid_call():
    text = read(SETUID)
    if "susfs_try_umount(" in text:
        report(SETUID, "already wired, leaving it alone")
        return

    # <linux/cred.h> is added on purpose: the call below uses current_uid(), and this file does not
    # include it (measured by the first CI run, which failed on exactly that assumption).
    text = insert_after_first_include(
        text,
        '#include <linux/cred.h>\n'
        '#include "susfs/susfs_try_umount.h"\t/* CONFIG_KSU_SUSFS_TRY_UMOUNT */\n',
        SETUID,
        "include the try_umount layer (and cred.h, for current_uid)",
    )

    # Upstream's order: the SUSFS paths come off first, then KernelSU's own umounts.  The uid is
    # carried for the feature's log line only (upstream carries it the same way and decides nothing
    # from it), and it is read from `current` rather than the work struct so this does not depend on
    # a field name in a tree this repository does not own.
    text = insert_before(
        text,
        "ksu_handle_setresuid(",
        "susfs_try_umount(current_uid().val);",
        SETUID,
        "call susfs_try_umount() before KernelSU's own umounts",
        indent_from=True,
    )

    write(SETUID, text)


# There is no wire_kbuild(): the workflow's object list is a glob over `susfs/*.c`, so the new
# source is compiled without an edit here, and an edit that added it again would list one object
# twice.  The workflow's own grep for `susfs_try_umount.o` in the Kbuild is what checks the glob
# really picked it up.


def main():
    print("wire_try_umount: wiring CONFIG_KSU_SUSFS_TRY_UMOUNT into the merged tree")
    wire_supercall()
    wire_layer()
    wire_setuid_call()
    print(f"wire_try_umount: {len(changes)} change(s) applied")


if __name__ == "__main__":
    main()
