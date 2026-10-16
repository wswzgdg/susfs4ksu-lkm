// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_memfd.c - memfd name blocking (SUSFS ADD_SUS_MEMFD).
 *
 * Upstream patches memfd_create() to call susfs_sus_memfd() and return -EINVAL
 * when the name is in the block list. An LKM kprobes __arm64_sys_memfd_create
 * and checks the name before the original runs.
 *
 * The kprobe is lazily registered: it only arms when the first blocked name
 * is added and disarms after the last one is removed, so no overhead on the
 * hot memfd_create() path when the feature is unused.
 */
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include "susfs_abi.h"
#include "susfs.h"	/* susfs_abi_path_ok */
#include "susfs_log.h"

#define SUSFS_MEMFD_MAX 32
#define SUSFS_MEMFD_MAX_NAME 248 /* SUSFS_MAX_LEN_MFD_NAME from upstream */

struct susfs_memfd_entry {
	char name[SUSFS_MEMFD_MAX_NAME];
	bool active;
};

static struct susfs_memfd_entry memfd_entries[SUSFS_MEMFD_MAX];
static atomic_t n_memfd;

/* Does the name match any entry? */
static bool susfs_memfd_blocked(const char *name)
{
	int i;

	for (i = 0; i < atomic_read(&n_memfd); i++) {
		if (READ_ONCE(memfd_entries[i].active) &&
		    strcmp(memfd_entries[i].name, name) == 0)
			return true;
	}
	return false;
}

/* Add a name to the block list. Returns 0 on success, -EEXIST if already
 * present, -ENOSPC if full. */
static int susfs_memfd_add(const char *name)
{
	int i, len, n;

	len = strlen(name);
	if (len == 0 || len >= SUSFS_MEMFD_MAX_NAME)
		return -EINVAL;

	if (susfs_memfd_blocked(name))
		return -EEXIST;

	for (i = 0; i < SUSFS_MEMFD_MAX; i++) {
		if (!READ_ONCE(memfd_entries[i].active)) {
			strscpy(memfd_entries[i].name, name,
				sizeof(memfd_entries[i].name));
			WRITE_ONCE(memfd_entries[i].active, true);
			n = atomic_inc_return(&n_memfd);
			SUSFS_LOGI("susfs_memfd: blocking %s (n=%d)\n", name, n);
			return 0;
		}
	}
	return -ENOSPC;
}

/* Remove a name from the block list. Returns 0 on success, -ENOENT if not
 * found. */
static int susfs_memfd_del(const char *name)
{
	int i;

	for (i = 0; i < atomic_read(&n_memfd); i++) {
		if (READ_ONCE(memfd_entries[i].active) &&
		    strcmp(memfd_entries[i].name, name) == 0) {
			WRITE_ONCE(memfd_entries[i].active, false);
			atomic_dec(&n_memfd);
			SUSFS_LOGI("susfs_memfd: unblocking %s (n=%d)\n",
				    name, atomic_read(&n_memfd));
			return 0;
		}
	}
	return -ENOENT;
}

/* ---- kprobe on __arm64_sys_memfd_create ----
 * memfd_create(const char __user *uname, unsigned int flags)
 * regs[0] = uname, regs[1] = flags
 *
 * We check the name BEFORE the original runs. If it's blocked, we set the
 * return value to -EINVAL and skip the rest of the function by returning 1
 * from the pre_handler.
 */
static int memfd_pre(struct kprobe *kp, struct pt_regs *regs)
{
	void __user *uname = (void __user *)regs->regs[0];
	char name[SUSFS_MEMFD_MAX_NAME];
	long n;

	/* Fast path: no blocked names → skip everything. */
	if (!atomic_read(&n_memfd))
		return 0;

	if (!uname)
		return 0;

	n = strncpy_from_user(name, uname, sizeof(name) - 1);
	if (n <= 0 || n == (long)sizeof(name) - 1)
		return 0;
	name[n] = '\0';

	if (susfs_memfd_blocked(name)) {
		SUSFS_LOGI("susfs_memfd: blocking memfd_create(%s)\n", name);
		regs->regs[0] = -EINVAL;
		regs->pc = regs->regs[30]; /* return from the syscall */
		return 1; /* skip the rest */
	}
	return 0;
}

static struct kprobe memfd_kp = {
	.symbol_name = "__arm64_sys_memfd_create",
	.pre_handler = memfd_pre,
};

static bool memfd_registered;

/* Lazy: register on first ADD, unregister after last DEL. */
static void memfd_probe_ensure(void)
{
	if (!memfd_registered) {
		int rc = register_kprobe(&memfd_kp);
		if (rc)
			pr_warn("susfs_memfd: register_kprobe failed %d\n", rc);
		else {
			memfd_registered = true;
			SUSFS_LOGI("susfs_memfd: kprobe armed\n");
		}
	}
}

static void memfd_probe_release(void)
{
	if (memfd_registered) {
		unregister_kprobe(&memfd_kp);
		memfd_registered = false;
		SUSFS_LOGI("susfs_memfd: kprobe released\n");
	}
}

int susfs_memfd_init(void)
{
	return 0; /* kprobe is lazily registered on first ADD */
}

void susfs_memfd_exit(void)
{
	memfd_probe_release();
}

bool susfs_memfd_active(void)
{
	return memfd_registered && atomic_read(&n_memfd) > 0;
}

/* SuperCall handler: CMD_SUSFS_ADD_SUS_MEMFD / CMD_SUSFS_DEL_SUS_MEMFD */
void susfs_memfd_supercall(unsigned int cmd, void __user **arg)
{
	struct st_susfs_sus_memfd info = {0};

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	if (!susfs_abi_path_ok(info.target_pathname,
			       sizeof(info.target_pathname))) {
		info.err = -EINVAL;
		goto out;
	}

	if (cmd == CMD_SUSFS_ADD_SUS_MEMFD) {
		memfd_probe_ensure();
		info.err = susfs_memfd_add(info.target_pathname);
	} else {
		int rc = susfs_memfd_del(info.target_pathname);
		if (!rc && atomic_read(&n_memfd) == 0)
			memfd_probe_release();
		info.err = rc;
	}
out:
	if (copy_to_user((void __user *)*arg, &info, sizeof(info)))
		pr_warn("susfs_memfd supercall copy_to_user failed\n");
}