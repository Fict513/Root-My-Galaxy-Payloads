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
 * project already avoids the same class of write in its own KernelSU delta: `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT`
 * makes `ksu_patch_text()` return `-EOPNOTSUPP` instead of patching, `ksu_syscall_table_hook()` returns
 * errors instead of pretending, and the features that need a hook reach for kprobes/kretprobes instead -
 * `samsung_defex.c` probes `task_defex_enforce` and answers through `regs->regs[0]`, and the AVC spoof
 * probes `slow_avc_audit`.
 *
 * So this file keeps upstream's API exactly - `ksu_lsm_hook_init()`, `ksu_lsm_hook_exit()`,
 * `ksu_register_lsm_hook()`, `ksu_unregister_lsm_hook()`, and the `KSU_LSM_HOOK_INSERT` declarations
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
 *   1. the SELinux implementation runs and its own answer stands - a denial is left alone;
 *   2. if it allowed (returned 0), the declared replacement is called with the arguments the
 *      implementation was called with, and a non-zero answer of its own replaces the 0. That is the
 *      "add a denial" half and nothing more, which is all the insert path could do either.
 *
 * The arguments are passed through as the raw register values captured on entry. That is not a trick:
 * every hook in the table below takes its inputs as pointer arguments in the leading registers
 * (`struct mnt_idmap *`, `struct inode *`, `struct dentry *`, `struct path *`, `struct kstatfs *`), and
 * the replacements read those pointers and return an int - the whole of what this shim relies on. A
 * hook whose replacement needed to *modify* an output buffer could not be honoured this way, and none
 * of theirs does: the insert path has no way to do that either.
 *
 * ## Why there is a slot per hook rather than shared handlers
 *
 * A kretprobe's handlers are given the instance and the registers, and nothing that names the probe
 * they belong to: `struct kretprobe_instance` carries no back pointer to its `struct kretprobe` on this
 * kernel (6.6 GKI - it is behind `rph`, and a rethook build has a different member again). Rather than
 * reach through either layout, each hook gets its own pair of thin handlers, generated with it, so the
 * probe each one belongs to is a compile-time fact. All thirteen share the same two bodies.
 *
 * ## What this costs, and what it does not do
 *
 * - A member with no slot in the table is refused with a log line naming it, rather than installed
 *   against something else. A hook that installs and does nothing is the failure this project
 *   distrusts most.
 * - Replace-shaped hooks (`hook->insert == false`, a function-pointer swap inside `selinux_hooks[]`)
 *   are refused with that reason: the swap is the read-only write that does not land here. Nothing in
 *   this tree declares one.
 * - The mechanism is version-independent, unlike upstream's. 6.12 and later dispatch LSM hooks through
 *   static calls instead of walking `security_hook_heads` and upstream's insert path does not exist
 *   there at all; a kretprobe on `selinux_*` is the same code on every KMI, which is why this file has
 *   no version branches in it.
 * - Nothing here writes to the `struct ksu_lsm_hook` it is handed. The declaration belongs to
 *   `sus_path.c`, and the probe that carries it lives in this file's own slot table.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/string.h>

#include "lsm_hook.h"
#include "susfs_log.h"

/* The most arguments any hook in the table takes is five (`inode_rename`); eight is what a shim can
 * pass through in registers without ever touching the stack. */
#define SUSFS_ARG_REGS 8

struct susfs_args {
	unsigned long arg[SUSFS_ARG_REGS];
};

struct susfs_slot {
	/* The member `sus_path.c` declares, matched against `hook->head_name` at registration. */
	const char *member;
	/* The SELinux implementation that decides it, resolved by `register_kretprobe` through
	 * kallsyms - the same lookup this module already depends on for its 97 imports, and the reason
	 * there is no address table here to keep in step with a kernel. */
	const char *symbol;
	kretprobe_handler_t entry;
	kretprobe_handler_t ret;
	struct kprobe *kp;
	const struct ksu_lsm_hook *hook;
};

/* The two bodies every hook's generated handlers call. */
static int susfs_capture(struct susfs_args *args, struct pt_regs *regs)
{
	int i;

	for (i = 0; i < SUSFS_ARG_REGS; i++)
		args->arg[i] = regs->regs[i];
	return 0;
}

static int susfs_verdict(const struct ksu_lsm_hook *hook, struct susfs_args *args,
			 struct pt_regs *regs)
{
	int verdict;

	/* The implementation's own answer stands. A denial is a denial, and the insert path could never
	 * have suppressed one either - only the pass-through case is ours. */
	if (regs->regs[0] != 0)
		return 0;
	if (!hook || !hook->replacement)
		return 0;

	/* The declared replacement, called with the arguments the implementation was called with.
	 * `hook->replacement` is `void *` because it carries thirteen different hook signatures; the ones
	 * in the table take pointer arguments and return an int, which is the whole of what is relied on
	 * here. */
	verdict = ((int (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long,
			    unsigned long, unsigned long, unsigned long))(hook->replacement))(
		args->arg[0], args->arg[1], args->arg[2], args->arg[3], args->arg[4], args->arg[5],
		args->arg[6], args->arg[7]);

	if (verdict != 0) {
		regs->regs[0] = (unsigned long)verdict;
		/* One answer is enough; nothing after this should re-argue the call. */
		return 1;
	}
	return 0;
}

#ifdef __aarch64__
/*
 * One pair of handlers and one probe per hook, from one line each. The probe is a file-scope static,
 * so a handler finds the declaration it belongs to without asking the instance anything.
 */
#define SUSFS_HOOK_SLOT(suffix, member_, symbol_)                                                  \
	static struct kretprobe susfs_probe_##suffix;                                              \
	static struct susfs_slot susfs_slot_##suffix = {                                           \
		.member = #member_,                                                                \
		.symbol = symbol_,                                                                 \
		.kp = &susfs_probe_##suffix.kp,                                                    \
	};                                                                                         \
	static int susfs_entry_##suffix(struct kretprobe_instance *ri, struct pt_regs *regs)        \
	{                                                                                          \
		return susfs_capture((struct susfs_args *)ri->data, regs);                         \
	}                                                                                          \
	static int susfs_ret_##suffix(struct kretprobe_instance *ri, struct pt_regs *regs)          \
	{                                                                                          \
		return susfs_verdict(susfs_slot_##suffix.hook, (struct susfs_args *)ri->data, regs); \
	}

SUSFS_HOOK_SLOT(inode_permission, inode_permission, "selinux_inode_permission")
SUSFS_HOOK_SLOT(inode_getattr, inode_getattr, "selinux_inode_getattr")
SUSFS_HOOK_SLOT(inode_unlink, inode_unlink, "selinux_inode_unlink")
SUSFS_HOOK_SLOT(inode_rmdir, inode_rmdir, "selinux_inode_rmdir")
SUSFS_HOOK_SLOT(inode_rename, inode_rename, "selinux_inode_rename")
SUSFS_HOOK_SLOT(inode_link, inode_link, "selinux_inode_link")
SUSFS_HOOK_SLOT(sb_statfs, sb_statfs, "selinux_sb_statfs")
SUSFS_HOOK_SLOT(inode_setattr, inode_setattr, "selinux_inode_setattr")
SUSFS_HOOK_SLOT(inode_getxattr, inode_getxattr, "selinux_inode_getxattr")
SUSFS_HOOK_SLOT(inode_listxattr, inode_listxattr, "selinux_inode_listxattr")
SUSFS_HOOK_SLOT(inode_setxattr, inode_setxattr, "selinux_inode_setxattr")
SUSFS_HOOK_SLOT(inode_removexattr, inode_removexattr, "selinux_inode_removexattr")
SUSFS_HOOK_SLOT(path_notify, path_notify, "selinux_path_notify")

#define SUSFS_HOOK_SLOT_ENTRY(suffix)                                                              \
	{                                                                                          \
		.slot = &susfs_slot_##suffix, .probe = &susfs_probe_##suffix,                       \
		.entry = susfs_entry_##suffix, .ret = susfs_ret_##suffix,                           \
	}

struct susfs_install {
	struct susfs_slot *slot;
	struct kretprobe *probe;
	kretprobe_handler_t entry;
	kretprobe_handler_t ret;
};

/* The table is the whole of which hooks can be installed: what `sus_path.c` declares, and what each
 * one probes. Order is irrelevant - registration looks the member up. */
static struct susfs_install susfs_installs[] = {
	SUSFS_HOOK_SLOT_ENTRY(inode_permission),
	SUSFS_HOOK_SLOT_ENTRY(inode_getattr),
	SUSFS_HOOK_SLOT_ENTRY(inode_unlink),
	SUSFS_HOOK_SLOT_ENTRY(inode_rmdir),
	SUSFS_HOOK_SLOT_ENTRY(inode_rename),
	SUSFS_HOOK_SLOT_ENTRY(inode_link),
	SUSFS_HOOK_SLOT_ENTRY(sb_statfs),
	SUSFS_HOOK_SLOT_ENTRY(inode_setattr),
	SUSFS_HOOK_SLOT_ENTRY(inode_getxattr),
	SUSFS_HOOK_SLOT_ENTRY(inode_listxattr),
	SUSFS_HOOK_SLOT_ENTRY(inode_setxattr),
	SUSFS_HOOK_SLOT_ENTRY(inode_removexattr),
	SUSFS_HOOK_SLOT_ENTRY(path_notify),
};
#endif /* __aarch64__ */

static DEFINE_MUTEX(susfs_hooks_lock);

/*
 * How many probes this layer may install, and whether it installs any.
 *
 * A panic on load cannot be debugged from the phone it took down, so the layer has to be able to run a
 * *prefix* of itself: load with `lsm_max=3` and, if that comes up while `lsm_max=4` does not, the fourth
 * hook is the one to look at. It was measured the hard way: the first build of this file rebooted an
 * SM-S938U1 on load, and a layer that installs thirteen probes in one go gives no way to tell which.
 */
static int lsm_max = -1;
module_param(lsm_max, int, 0644);
MODULE_PARM_DESC(lsm_max, "install at most this many probes (-1 installs every hook the caller declares)");

static bool lsm_off;
module_param(lsm_off, bool, 0644);
MODULE_PARM_DESC(lsm_off, "install no probes at all (diagnostic)");

/* Incremented as probes are installed, so the prefix above is the order the caller registers in. */
static int susfs_installed;

#ifdef __aarch64__
static struct susfs_install *susfs_install_for(const char *member)
{
	size_t i;

	if (!member)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(susfs_installs); i++) {
		if (!strcmp(susfs_installs[i].slot->member, member))
			return &susfs_installs[i];
	}
	return NULL;
}
#endif

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
	if (!hook || !hook->replacement) {
		pr_err("lsm_hook: nothing to install\n");
		return -EINVAL;
	}

	/* A swap needs the read-only write this file exists to avoid, so it is refused with its reason
	 * rather than installed and left doing nothing. */
	/* The bisect: a refusal is something sus_path reports and the module acts on, where a panic is a
	 * reboot with no evidence - so a bounded run has to stop *before* the probe that would crash. */
	if (lsm_off || (lsm_max >= 0 && susfs_installed >= lsm_max)) {
		pr_warn("lsm_hook: %s: not installed (lsm_off=%d lsm_max=%d, %d already installed)\n",
			hook->head_name ?: "unknown", lsm_off, lsm_max, susfs_installed);
		return -EOPNOTSUPP;
	}

	if (!hook->insert) {
		pr_err("lsm_hook: %s: replace-shaped hooks need a write into read-only kernel memory, "
		       "which this kernel refuses; declare it with KSU_LSM_HOOK_INSERT instead\n",
		       hook->head_name ?: "unknown");
		return -EOPNOTSUPP;
	}

#ifndef __aarch64__
	pr_err("lsm_hook: %s: this install path is arm64 only\n", hook->head_name ?: "unknown");
	return -EOPNOTSUPP;
#else
	{
		struct susfs_install *install;
		int ret;

		install = susfs_install_for(hook->head_name);
		if (!install) {
			pr_err("lsm_hook: %s: no SELinux implementation is known for this member; "
			       "refusing to install it against something else\n",
			       hook->head_name ?: "unknown");
			return -ENOENT;
		}

		mutex_lock(&susfs_hooks_lock);
		if (install->slot->hook) {
			mutex_unlock(&susfs_hooks_lock);
			pr_err("lsm_hook: %s: already installed\n", hook->head_name ?: "unknown");
			return -EEXIST;
		}

		install->probe->kp.symbol_name = install->slot->symbol;
		install->probe->entry_handler = install->entry;
		/* The return handler is `handler` in this API; `ret_handler` does not exist. */
		install->probe->handler = install->ret;
		install->probe->data_size = sizeof(struct susfs_args);
		/* The ceiling on concurrent captured calls, not a pool sized to the workload: a path lookup
		 * can re-enter one of these hooks, and a call that cannot get an instance is simply not
		 * intercepted - the kernel counts those as misses. */
		install->probe->maxactive = 64;

		ret = register_kretprobe(install->probe);
		if (ret) {
			mutex_unlock(&susfs_hooks_lock);
			pr_err("lsm_hook: %s: kretprobe on %s refused: %d\n",
			       hook->head_name ?: "unknown", install->slot->symbol, ret);
			return ret;
		}
		install->slot->hook = hook;
		susfs_installed++;
		mutex_unlock(&susfs_hooks_lock);

		SUSFS_LOGI("lsm_hook: %s: kretprobe armed on %s\n", hook->head_name ?: "unknown",
			   install->slot->symbol);
	}
	return 0;
#endif
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
#ifndef __aarch64__
	(void)hook;
#else
	if (!hook)
		return;

	mutex_lock(&susfs_hooks_lock);
	{
		struct susfs_install *install = susfs_install_for(hook->head_name);

		if (install && install->slot->hook == hook) {
			install->slot->hook = NULL;
			mutex_unlock(&susfs_hooks_lock);
			/* Cleared before the call, so a re-register cannot find a probe that is being taken
			 * down; `unregister_kretprobe()` waits for the handlers already running. */
			unregister_kretprobe(install->probe);
			SUSFS_LOGI("lsm_hook: %s: kretprobe removed\n", hook->head_name ?: "unknown");
			return;
		}
	}
	mutex_unlock(&susfs_hooks_lock);
	/* Not a state this tree reaches: `sus_path.c` unregisters what it registered. Said out loud so a
	 * mismatch shows up in the log rather than as a hook that quietly stayed armed. */
	pr_warn("lsm_hook: %s: nothing was installed under this declaration\n", hook->head_name ?: "unknown");
#endif
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
	/* Nothing global is armed: every probe belongs to a hook the caller registered and the caller's
	 * own teardown removes it. Saying that beats a silent no-op that reads like a leak. */
	SUSFS_LOGI("lsm_hook: exit (probes are owned by the hooks that registered them)\n");
}
