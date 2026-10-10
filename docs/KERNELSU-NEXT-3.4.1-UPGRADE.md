# KernelSU-Next v3.4.1 upgrade

`kernelsu/patches/KernelSU-Next-v3.4.1-samsung-kdp-rkp-defex.patch`, produced by rebasing the v3.4.0
patch onto upstream's `v3.4.1` (`8f902ae`, released 2026-10-09).

## What v3.4.1 is

A real release, not a version bump. Against v3.4.0 upstream added a second architecture's worth of hook
plumbing and moved the syscall-hook machinery around:

- `kernel/hook/riscv64/` — a new directory, and `#if defined(__riscv)` includes in the hook manager;
- `kernel/hook/syscall_event_bridge.c` and its header — the syscall event plumbing now lives in its own
  file rather than inline in `syscall_hook_manager.c`;
- changes across `kernel/Kbuild`, `core/init.c`, `feature/{adb_root,selinux_hide,sucompat}.c`,
  `hook/{patch_memory.h,syscall_hook.h,syscall_hook_manager.c}`, `include/{arch,klog}.h`;
- in the daemon: `apk_sign.rs`, `assets.rs`, `cli.rs`, `defs.rs`, `init_event.rs`, `installer.sh`,
  `ksucalls.rs`, and `late_load.rs`, which gained `ScriptWait` — its stage scripts now take an explicit
  wait rather than a bool.

## The three conflicts, and how each was resolved

Applied with `patch -p1 --merge`, which left conflicts in three files. Two were re-anchoring, not
semantics: this patch is **pure addition** (+327 lines, no deletions) to the hook manager, so what broke
was where upstream had moved, not what either side wanted.

### 1. `kernel/hook/syscall_hook_manager.c` — 2 lines against 297

The largest conflict by text and the smallest by meaning. Upstream's side is its own new
`#if defined(__riscv) #include "hook/riscv64/syscall_regs.h"`; this patch's side is its ~298-line Samsung
block, which belongs after the includes and before `#ifdef CONFIG_KRETPROBES`.

**Resolution:** the block is re-anchored to that position, and upstream's riscv include is kept. Applied
with `-F 3`, the two later hunks (inside `ksu_syscall_hook_manager_init`) landed at offsets of 4 lines,
which is upstream's own shift for the two functions in that file.

### 2. `userspace/ksud/src/late_load.rs` — the only hand merge

This patch makes five changes there, and v3.4.1 changed the same file, so the hunks were merged by hand:

| this patch | v3.4.1 | resolution |
|---|---|---|
| drops `use std::process::Command` | import is now `use std::{process::Command, time::Instant};` | import becomes `use std::time::Instant;` — `Command` exists only for the manager-restart block this patch deletes, and upstream's new `Instant`/`ScriptWait` usage is untouched |
| `run(package_name` → `_package_name`, and no `utils::daemonize(false)?` | unchanged | applied as-is; the parameter is unused once the restart block is gone |
| stages the daemon (`stage_daemon_from("/data/local/tmp/.ksud-stage")`) as its first act | unchanged | applied as-is |
| `utils::install(None)` → `utils::finish_install(None)` | unchanged | applied as-is |
| deletes the manager-restart block (`am force-stop` / `am start`) | unchanged | applied as-is — this daemon is headless and the app relaunches the manager |

Upstream's new `ScriptWait` stages (`run_stage("service", ScriptWait::NoWait)`) are left exactly as
v3.4.1 has them.

### 3. `kernel/core/init.c` — a context collision

This patch inserts the KDP/DEFEX includes, an `extern void ksu_avc_spoof_late_init(void);`, `int ret;`,
and the two Samsung init calls with their error unwinding. v3.4.1 moved the same lines the hunk's context
anchored to. **Resolution:** applied with `-F 3` and then checked by reading the result — all five
insertions are present at the right places (`ksu_samsung_kdp_init()` at 147, `ksu_samsung_defex_init()`
at 158, `ksu_avc_spoof_late_init()` at 200).

## How far this is validated

- The patch **applies cleanly** to a fresh `v3.4.1` checkout (`git apply --check`, then applied).
- The applied tree carries the delta: `kernel/compat/{samsung_kdp.c,samsung_defex.c,samsung_defex.h}`,
  `kernel/include/ksu_samsung_kdp.h`, 62 `samsung` lines in the hook manager, and `late_load.rs` with
  `_package_name`, `stage_daemon_from` and `finish_install`.
- The guards `ksu-build.yml` runs on a built module hold here at the source level: no `df.root`.

## What is still to do

**It has not been compiled.** That is what `ksu-build.yml` is for, and it takes the ref it is asked to
build: `ksu_ref: v3.4.1` with `flavor: kernelsu-next`. The first run of that is the first thing that will
tell whether the re-anchored block compiles.

**Nothing is published.** A v3.4.1 daemon only reaches phones once that build runs and whatever serves
the generic KernelSU-Next daemon is pointed at the artifact it produces. Until then the feed keeps
serving the v3.4.0 daemon, and the app's `KernelSuFlavor.KernelSuNext.defaultManagerVersion` stays at
`3.4.0` on purpose — that value tracks the daemon this project ships, not upstream's newest tag.

**The other flavours are untouched.** KernelSU (v3.2.5/v3.3.0) and BakaSU (v4.2.0-rc2/rc3) have their own
patches and their own refs; this document is only about KernelSU-Next.
