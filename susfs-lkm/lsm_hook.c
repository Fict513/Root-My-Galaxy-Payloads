// SPDX-License-Identifier: GPL-2.0
/*
 * The LSM layer, installed with kretprobes instead of a write into security_hook_heads.
 *
 * ## Why this replaces the upstream file
 *
 * Upstream's `lsm_hook.c` publishes a `struct security_hook_list` by writing it into
 * `security_hook_heads` (or into the `selinux_hooks[]` slot it found by symbol identity) - memory that
 * is `__lsm_ro_after_init`, read-only once the kernel has booted. It makes that write land by
 * translating the address to a physical one, mapping it through a fixmap and storing through
 * `copy_to_kernel_nofault` under `stop_machine`.
 *
 * On Samsung kernels that write does not land. Measured on an SM-S938U1 (`6.6.127-android15-8-...-4k`,
 * SELinux enforcing): the module loaded, resolved 97/97 symbols, found the `inode_getattr` list by
 * identity at offset 0x1c8, and then
 *
 *     lsm_hook: failed to insert inode_getattr at the head of its list: -14
 *     sus_path: getattr hook failed -14 - nothing would be hidden, refusing to load
 *
 * `-14` is `EFAULT` out of that read-only write, and the module refused to load - correctly. This
 * project already avoids the same class of write in its own KernelSU delta: there,
 * `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT` makes `ksu_patch_text()` return `-EOPNOTSUPP` instead of patching,
 * `ksu_syscall_table_hook()` returns errors instead of pretending, and the features that need a hook
 * reach for kprobes/kretprobes instead - `samsung_defex.c` probes `task_defex_enforce` and clears its
 * verdict through `regs->regs[0]`, and the AVC spoof probes `slow_avc_audit`.
 *
 * So this file keeps upstream's API exactly - `ksu_lsm_hook_init()`, `ksu_lsm_hook_exit()`,
 * `ksu_register_lsm_hook()`, `ksu_unregister_lsm_hook()`, and the `KSU_LSM_HOOK_INSERT` declaration
 * `sus_path.c` writes - and changes only *how* a declared hook is installed: a kretprobe on the SELinux
 * implementation of that member, whose return it may change.
 *
 * ## Why one generic shim is faithful to what the insert path did
 *
 * Upstream's own contract for insert-shaped hooks (`lsm_hook.h`): the hook runs *before* every
 * registered LSM, its replacement must not call any original, and it can only **add a denial**
 * (`-ENOENT`) - it can never suppress another LSM's decision, and it must return 0 on the
 * pass-through path. Every hook `sus_path.c` declares is insert-shaped.
 *
 * That maps onto a kretprobe exactly:
 *
 *   1. the SELinux implementation runs and its own answer stands - if it denied, that value is left
 *      alone;
 *   2. if it allowed (returned 0), the declared replacement is called with the arguments the
 *      implementation was called with, and a non-zero answer of its own replaces the 0. That is the
 *      "add a denial" half and nothing more, which is all the insert path could do.
 *
 * The arguments are passed through as the raw register values captured on entry. That is not a trick:
 * every hook in the table below takes its inputs as pointer arguments in the leading registers
 * (`struct mnt_idmap *`, `struct inode *`, `struct dentry *`, `struct path *`, `struct kstatfs *`), and
 * the replacements read those pointers and return an int - the whole of what this shim relies on. A
 * hook whose replacement needed to *modify* an output buffer could not be honoured this way, and none
 * of theirs does: the insert path has no way to do that either.
 *
 * ## What this costs, and what it does not do
 *
 * - A member with no known SELinux implementation is refused with a log line naming it, rather than
 *   installed against something else. A hook that installs and does nothing is the failure this
 *   project distrusts most.
 * - Replace-shaped hooks (`hook->insert == false`, a function-pointer swap inside `selinux_hooks[]`)
 *   are refused with that reason: the swap is the read-only write that does not land here. Nothing in
 *   this tree declares one, and `sus_path.c` declares none.
 * - The mechanism is version-independent, unlike upstream's. 6.12 and later dispatch LSM hooks through
 *   static calls instead of walking `security_hook_heads`, and upstream's insert path does not exist
 *   there at all; a kretprobe on `selinux_*` is the same code on every KMI, which is why this file has
 *   no version branches in it.
 * - Nothing here writes to the `struct ksu_lsm_hook` it is handed. The declaration belongs to
 *   `sus_path.c`, and the probe that carries it is kept in this file's own registry - so a hook can be
 *   registered and removed without a field being added to upstream's struct.
 */

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "lsm_hook.h"
#include "susfs_log.h"

/* The most arguments any hook in the table takes is five (`inode_rename`); eight is what a shim can
 * pass through in registers without ever touching the stack. */
#define SUSFS_ARG_REGS 8

/* `sus_path.c` registers 13 hooks (two required, eleven extra). A little room, and a fixed table:
 * this is a load-time list, not a data structure to grow. */
#define SUSFS_MAX_HOOKS 16

struct susfs_probe {
	struct kretprobe probe;
	const struct ksu_lsm_hook *hook;
};

/* What the entry handler leaves for the return handler. */
struct susfs_args {
	unsigned long arg[SUSFS_ARG_REGS];
};

static struct susfs_probe *susfs_probes[SUSFS_MAX_HOOKS];
static DEFINE_MUTEX(susfs_probes_lock);

/* `<member>` -> the SELinux implementation that decides it.
 *
 * Named rather than addressed: `register_kprobe()` resolves `kp.symbol_name` through kallsyms, which is
 * the same lookup this module already depends on for its 97 imports, and it is why there is no symbol
 * table here to keep in step with the kernel. The member is what `sus_path.c` declared; `selinux_<member>`
 * is what answers, and probing it is what lets the declared replacement answer on top of that answer. */
static const char *susfs_selinux_symbol(const char *member)
{
	if (!member)
		return NULL;
	if (!strcmp(member, "inode_permission"))
		return "selinux_inode_permission";
	if (!strcmp(member, "inode_getattr"))
		return "selinux_inode_getattr";
	if (!strcmp(member, "inode_unlink"))
		return "selinux_inode_unlink";
	if (!strcmp(member, "inode_rmdir"))
		return "selinux_inode_rmdir";
	if (!strcmp(member, "inode_rename"))
		return "selinux_inode_rename";
	if (!strcmp(member, "inode_link"))
		return "selinux_inode_link";
	if (!strcmp(member, "sb_statfs"))
		return "selinux_sb_statfs";
	if (!strcmp(member, "inode_setattr"))
		return "selinux_inode_setattr";
	if (!strcmp(member, "inode_getxattr"))
		return "selinux_inode_getxattr";
	if (!strcmp(member, "inode_listxattr"))
		return "selinux_inode_listxattr";
	if (!strcmp(member, "inode_setxattr"))
		return "selinux_inode_setxattr";
	if (!strcmp(member, "inode_removexattr"))
		return "selinux_inode_removexattr";
	if (!strcmp(member, "path_notify"))
		return "selinux_path_notify";
	return NULL;
}

#ifdef __aarch64__

static int susfs_probe_entry(struct kretprobe_instance *instance, struct pt_regs *regs)
{
	struct susfs_args *args = (struct susfs_args *)instance->data;
	int i;

	for (i = 0; i < SUSFS_ARG_REGS; i++)
		args->arg[i] = regs->regs[i];
	return 0;
}

static int susfs_probe_return(struct kretprobe_instance *instance, struct pt_regs *regs)
{
	struct susfs_probe *probe = container_of(instance->rp, struct susfs_probe, probe);
	struct susfs_args *args = (struct susfs_args *)instance->data;
	const struct ksu_lsm_hook *hook = probe->hook;
	int verdict;

	/* The implementation's own answer stands. A denial is a denial, and the insert path could never
	 * have suppressed one either - only the pass-through case is ours. */
	if (regs->regs[0] != 0)
		return 0;

	if (!hook->replacement)
		return 0;

	/* The declared replacement, called with the arguments the implementation was called with.
	 * `hook->replacement` is `void *` because it carries 13 different hook signatures; the ones in the
	 * table take pointer arguments and return an int, which is the whole of what is relied on here. */
	verdict = ((int (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long,
			    unsigned long, unsigned long, unsigned long))(hook->replacement))(
		args->arg[0], args->arg[1], args->arg[2], args->arg[3], args->arg[4], args->arg[5],
		args->arg[6], args->arg[7]);

	if (verdict != 0) {
		regs->regs[0] = (unsigned long)verdict;
		/* One handler answering is enough; nothing after this should re-argue the call. */
		return 1;
	}
	return 0;
}

#endif /* __aarch64__ */

/* The registry, so a hook can be removed by the same pointer it was registered with - and so nothing
 * has to be written into the caller's declaration to remember what was installed. */
static struct susfs_probe *susfs_probe_find(const struct ksu_lsm_hook *hook)
{
	int i;

	for (i = 0; i < SUSFS_MAX_HOOKS; i++) {
		if (susfs_probes[i] && susfs_probes[i]->hook == hook)
			return susfs_probes[i];
	}
	return NULL;
}

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
	struct susfs_probe *probe;
	const char *symbol;
	int slot = -1;
	int ret;
	int i;

	if (!hook || !hook->replacement) {
		pr_err("lsm_hook: nothing to install\n");
		return -EINVAL;
	}

	/* A swap needs the read-only write this file exists to avoid, so it is refused with its reason
	 * rather than installed and left doing nothing. */
	if (!hook->insert) {
		pr_err("lsm_hook: %s: replace-shaped hooks need a write into read-only kernel memory, "
		       "which this kernel refuses; declare it with KSU_LSM_HOOK_INSERT instead\n",
		       hook->head_name ?: "unknown");
		return -EOPNOTSUPP;
	}

	symbol = susfs_selinux_symbol(hook->head_name);
	if (!symbol) {
		pr_err("lsm_hook: %s: no SELinux implementation is known for this member; refusing to "
		       "install it against something else\n",
		       hook->head_name ?: "unknown");
		return -ENOENT;
	}

#ifndef __aarch64__
	pr_err("lsm_hook: %s: this install path is arm64 only\n", hook->head_name ?: "unknown");
	return -EOPNOTSUPP;
#else
	probe = kzalloc(sizeof(*probe), GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	probe->hook = hook;
	probe->probe.kp.symbol_name = symbol;
	probe->probe.entry_handler = susfs_probe_entry;
	probe->probe.ret_handler = susfs_probe_return;
	probe->probe.data_size = sizeof(struct susfs_args);
	/* The ceiling on concurrent captured calls, not a pool sized to the workload: a path lookup can
	 * re-enter one of these hooks, and a call that cannot get an instance is simply not intercepted
	 * (the kernel counts those as misses). */
	probe->probe.maxactive = 64;

	mutex_lock(&susfs_probes_lock);
	if (susfs_probe_find(hook)) {
		mutex_unlock(&susfs_probes_lock);
		kfree(probe);
		pr_err("lsm_hook: %s: already installed\n", hook->head_name ?: "unknown");
		return -EEXIST;
	}
	for (i = 0; i < SUSFS_MAX_HOOKS; i++) {
		if (!susfs_probes[i]) {
			slot = i;
			break;
		}
	}
	mutex_unlock(&susfs_probes_lock);

	if (slot < 0) {
		kfree(probe);
		pr_err("lsm_hook: %s: the registry is full (%d hooks)\n", hook->head_name ?: "unknown",
		       SUSFS_MAX_HOOKS);
		return -ENOSPC;
	}

	ret = register_kretprobe(&probe->probe);
	if (ret) {
		pr_err("lsm_hook: %s: kretprobe on %s refused: %d\n", hook->head_name ?: "unknown", symbol,
		       ret);
		kfree(probe);
		return ret;
	}

	mutex_lock(&susfs_probes_lock);
	susfs_probes[slot] = probe;
	mutex_unlock(&susfs_probes_lock);

	SUSFS_LOGI("lsm_hook: %s: kretprobe armed on %s\n", hook->head_name ?: "unknown", symbol);
	return 0;
#endif
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
	struct susfs_probe *probe;
	int i;

	if (!hook)
		return;

	mutex_lock(&susfs_probes_lock);
	for (i = 0; i < SUSFS_MAX_HOOKS; i++) {
		if (susfs_probes[i] && susfs_probes[i]->hook == hook) {
			probe = susfs_probes[i];
			susfs_probes[i] = NULL;
			mutex_unlock(&susfs_probes_lock);
			/* Out of the registry first, so a re-register cannot find a probe that is being
			 * taken down. `unregister_kretprobe()` waits for the handlers already running. */
			unregister_kretprobe(&probe->probe);
			kfree(probe);
			SUSFS_LOGI("lsm_hook: %s: kretprobe removed\n", hook->head_name ?: "unknown");
			return;
		}
	}
	mutex_unlock(&susfs_probes_lock);
	/* Not an error this tree can reach: `sus_path.c` unregisters what it registered. Said out loud so
	 * a mismatch shows up in the log rather than as a hook that quietly stayed armed. */
	pr_warn("lsm_hook: %s: nothing was installed under this declaration\n",
		   hook->head_name ?: "unknown");
}

/* The two entry points the header carries that this install path has no separate use for: an
 * insert-shaped registration *is* the hook. Kept so the API the rest of the tree links against is
 * unchanged. */
int ksu_lsm_hook(struct ksu_lsm_hook *hook)
{
	return ksu_register_lsm_hook(hook);
}

void ksu_lsm_unhook(struct ksu_lsm_hook *hook)
{
	ksu_unregister_lsm_hook(hook);
}

void ksu_lsm_hook_init(void)
{
	SUSFS_LOGI("lsm_hook: install path is kretprobe-based - security_hook_heads is read-only here and "
		   "the write that publishes a hook into it does not land\n");
}

void ksu_lsm_hook_exit(void)
{
	/* Nothing global is armed: every probe belongs to a hook the caller registered and the caller's own
	 * teardown removes it. Saying that beats a silent no-op that reads like a leak. */
	SUSFS_LOGI("lsm_hook: exit (probes are owned by the hooks that registered them)\n");
}
