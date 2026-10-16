// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_proc_fd_link.c - independent /proc/self/fd/<N> symlink spoofing.
 *
 * Upstream's LH_SUS_PROC_FD_LINK is called from vfs_readlink()/do_proc_readlink()
 * to rewrite the symlink target of /proc/<pid>/fd/N entries.  This LKM cannot
 * patch VFS, so it kretprobes d_path() (the lowest common denominator that
 * proc_pid_readlink() reaches) and rewrites the produced path string.
 *
 * The kretprobe runs after susfs_open_redirect's own d_path() probe (registered
 * first in the layer table).  Return handlers fire in reverse registration
 * order, so this one sees the original path and open_redirect sees whatever we
 * left behind.  The two rule sets are disjoint in practice (open_redirect
 * targets real filesystem paths, proc_fd_link targets /proc/<pid>/fd/N paths),
 * so the ordering is harmless.
 *
 * The kretprobe is lazily registered: it only arms when the first rule is
 * added and disarms after the last one is removed, so no overhead on the
 * hot d_path() path when the feature is unused.
 */
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/types.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "ksu_umount_gate.h"
#include "susfs_kprobe.h"

#define PFDL_MAX 32
#define PFDL_MAX_NAME 256

struct pfld_entry {
	char target[PFDL_MAX_NAME];
	char spoofed[PFDL_MAX_NAME];
	bool active;
};

static struct pfld_entry pfld_entries[PFDL_MAX];
static atomic_t npfld;

/* App-uid gate: same as sus_path / sus_map. */
static bool pfld_gate_ok(void)
{
	return susfs_is_current_proc_umounted_app();
}

static bool pfld_match(const char *path, char *out, int outlen)
{
	int n = atomic_read(&npfld);
	int i;

	if (!n || !pfld_gate_ok())
		return false;

	for (i = 0; i < n; i++) {
		if (READ_ONCE(pfld_entries[i].active) &&
		    strcmp(path, pfld_entries[i].target) == 0) {
			strscpy(out, pfld_entries[i].spoofed, outlen);
			return true;
		}
	}
	return false;
}

/* ---- d_path() kretprobe ---- */

struct pfld_dpath_args {
	char *buf;
	int buflen;
};

static int pfld_dpath_entry(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct pfld_dpath_args *a = (struct pfld_dpath_args *)ri->data;

	a->buf = (char *)regs->regs[1];
	a->buflen = (int)regs->regs[2];
	return 0;
}

static int pfld_dpath_ret(struct kretprobe_instance *ri,
			  struct pt_regs *regs)
{
	struct pfld_dpath_args *a = (struct pfld_dpath_args *)ri->data;
	char *ret;
	char spoofed[PFDL_MAX_NAME];

	if (!a->buf || a->buflen <= 0)
		return 0;

	ret = (char *)regs->regs[0];
	if (IS_ERR(ret))
		return 0;

	if (!pfld_match(ret, spoofed, sizeof(spoofed)))
		return 0;

	if (strnlen(spoofed, (size_t)a->buflen) >= (size_t)a->buflen)
		return 0;

	strscpy(a->buf, spoofed, (size_t)a->buflen);
	regs->regs[0] = (unsigned long)a->buf;
	SUSFS_LOGI("pfld: %s -> %s\n", ret, spoofed);
	return 0;
}

static struct kretprobe kr_pfld = {
	.kp.symbol_name = "d_path",
	.entry_handler = pfld_dpath_entry,
	.handler = pfld_dpath_ret,
	.data_size = sizeof(struct pfld_dpath_args),
	.maxactive = 16,
};
static bool pfld_registered;

/* Lazy: register on first ADD, unregister after last DEL. */
static void pfld_probe_ensure(void)
{
	if (!pfld_registered) {
		int rc = register_kretprobe(&kr_pfld);
		if (rc) {
			susfs_krp_forget_addr(&kr_pfld);
			pr_warn("pfld: register_kretprobe failed %d\n", rc);
		} else {
			pfld_registered = true;
			SUSFS_LOGI("pfld: kretprobe armed\n");
		}
	}
}

static void pfld_probe_release(void)
{
	if (pfld_registered) {
		unregister_kretprobe(&kr_pfld);
		susfs_krp_forget_addr(&kr_pfld);
		pfld_registered = false;
		SUSFS_LOGI("pfld: kretprobe released\n");
	}
}

/* ---- supercall ---- */

void susfs_proc_fd_link_supercall(unsigned int cmd, void __user **arg)
{
	struct st_susfs_sus_proc_fd_link info = {0};

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	if (!susfs_abi_path_ok(info.target_link_name,
			       sizeof(info.target_link_name))) {
		info.err = -EINVAL;
		goto out;
	}
	if (!susfs_abi_path_ok(info.spoofed_link_name,
			       sizeof(info.spoofed_link_name))) {
		info.err = -EINVAL;
		goto out;
	}

	if (cmd == CMD_SUSFS_ADD_SUS_PROC_FD_LINK) {
		int i, len;

		len = strlen(info.target_link_name);
		if (len == 0 || len >= PFDL_MAX_NAME) {
			info.err = -EINVAL;
			goto out;
		}
		/* dup check */
		for (i = 0; i < atomic_read(&npfld); i++) {
			if (READ_ONCE(pfld_entries[i].active) &&
			    strcmp(pfld_entries[i].target,
				   info.target_link_name) == 0) {
				info.err = -EEXIST;
				goto out;
			}
		}
		pfld_probe_ensure();
		for (i = 0; i < PFDL_MAX; i++) {
			if (!READ_ONCE(pfld_entries[i].active)) {
				strscpy(pfld_entries[i].target,
					info.target_link_name,
					sizeof(pfld_entries[i].target));
				strscpy(pfld_entries[i].spoofed,
					info.spoofed_link_name,
					sizeof(pfld_entries[i].spoofed));
				WRITE_ONCE(pfld_entries[i].active, true);
				atomic_inc(&npfld);
				info.err = 0;
				goto out;
			}
		}
		info.err = -ENOSPC;
		goto out;
	}

	/* CMD_SUSFS_DEL_SUS_PROC_FD_LINK */
	{
		int i;
		for (i = 0; i < atomic_read(&npfld); i++) {
			if (READ_ONCE(pfld_entries[i].active) &&
			    strcmp(pfld_entries[i].target,
				   info.target_link_name) == 0) {
				WRITE_ONCE(pfld_entries[i].active, false);
				atomic_dec(&npfld);
				if (atomic_read(&npfld) == 0)
					pfld_probe_release();
				info.err = 0;
				goto out;
			}
		}
		info.err = -ENOENT;
	}
out:
	if (copy_to_user(&((struct st_susfs_sus_proc_fd_link __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("pfld supercall copy_to_user failed\n");
}

int susfs_proc_fd_link_init(void)
{
	return 0; /* kretprobe is lazily registered on first ADD */
}

void susfs_proc_fd_link_exit(void)
{
	pfld_probe_release();
}

bool susfs_proc_fd_link_active(void)
{
	return pfld_registered && atomic_read(&npfld) > 0;
}