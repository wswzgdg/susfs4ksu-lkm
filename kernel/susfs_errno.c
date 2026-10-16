// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_errno.c - errno spoofing based on path prefix (SUSFS SUS_ERROR_NO).
 *
 * Upstream patches VFS functions to call susfs_change_error_no_by_pathname()
 * before performing the operation. An LKM cannot patch VFS, so this hooks the
 * syscall table entries instead: the wrapper reads the filename argument,
 * checks the prefix, and returns the errno WITHOUT calling the original when it
 * matches. The operation is never performed, so there is no "undo" problem.
 *
 * Path prefixes and errnos mirror upstream's table, including syscall-family
 * differentiation: /system/ + RENAMEAT2_OLDNAME returns -EXDEV, not -EROFS.
 *
 * Only app-uid callers (uid >= 10000) are affected; root and init get the real
 * answer. The gate is the same question sus_path asks KernelSU (ksu_umount_gate).
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"
#include "susfs_fp_hook.h"
#include "ksu_umount_gate.h"

#define SUSFS_ERRNO_MAX_PATH 512

/* Module parameter: enable errno spoofing (default off).
 * Set to 1 before or at load time to arm the syscall hooks. */
static bool errno_enable;
module_param(errno_enable, bool, 0644);
MODULE_PARM_DESC(errno_enable, "Enable errno spoofing for app-uid callers");

/* ---- syscall family ids (upstream st_susfs_try_umount table) ---- */
enum susfs_errno_family {
	SUSFS_FAMILY_ALL_ENOENT,
	SUSFS_FAMILY_OPENAT,
	SUSFS_FAMILY_MKDIRAT,
	SUSFS_FAMILY_UNLINKAT,
	SUSFS_FAMILY_SYMLINKAT_NEWNAME,
	SUSFS_FAMILY_LINKAT_OLDNAME,
	SUSFS_FAMILY_LINKAT_NEWNAME,
	SUSFS_FAMILY_RENAMEAT2_OLDNAME,
	SUSFS_FAMILY_RENAMEAT2_NEWNAME,
};

/* ---- path-prefix table ---- */
struct susfs_errno_prefix {
    const char *prefix;
    size_t len;
};

static const struct susfs_errno_prefix errno_prefixes[] = {
    { "/system/",  8 },
    { "/vendor/",  8 },
    { "/storage/emulated/0/Android/data/", 33 },
    { "/dev/",     5 },
    { "/data/",    6 },
    { "/storage/", 9 },
};

#define SUSFS_ERRNO_NPREFIX ARRAY_SIZE(errno_prefixes)

/* Find which prefix @path matches. Returns the index, or -1 when none. */
static int susfs_errno_prefix_match(const char *path, size_t len)
{
    size_t i;

    for (i = 0; i < SUSFS_ERRNO_NPREFIX; i++) {
        if (len >= errno_prefixes[i].len &&
            strncmp(path, errno_prefixes[i].prefix,
                    errno_prefixes[i].len) == 0)
            return (int)i;
    }
    return -1;
}

/*
 * Returns the errno to set for the given (prefix_index, family), or 0 when no
 * blocking should occur. Mirrors upstream's susfs_change_error_no_by_pathname().
 */
static int susfs_errno_errno_for(int pfx, int family)
{
    switch (pfx) {
    case 0: /* /system/ */
    case 1: /* /vendor/ */
        switch (family) {
        case SUSFS_FAMILY_ALL_ENOENT:
        case SUSFS_FAMILY_LINKAT_OLDNAME:
            return -ENOENT;
        case SUSFS_FAMILY_RENAMEAT2_OLDNAME:
            return -EXDEV;
        default:
            return -EROFS;
        }
    case 2: /* /storage/emulated/0/Android/data/ */
    case 3: /* /dev/ */
    case 4: /* /data/ */
        switch (family) {
        case SUSFS_FAMILY_ALL_ENOENT:
        case SUSFS_FAMILY_UNLINKAT:
        case SUSFS_FAMILY_LINKAT_OLDNAME:
            return -ENOENT;
        case SUSFS_FAMILY_MKDIRAT:
        case SUSFS_FAMILY_SYMLINKAT_NEWNAME:
            return -EACCES;
        case SUSFS_FAMILY_LINKAT_NEWNAME:
        case SUSFS_FAMILY_RENAMEAT2_OLDNAME:
        case SUSFS_FAMILY_RENAMEAT2_NEWNAME:
            return -EXDEV;
        default:
            return -ENOENT;
        }
    case 5: /* /storage/ (generic fallback) */
    default:
        return -ENOENT;
    }
}

/* App-uid gate: same question sus_path asks KernelSU. */
static bool susfs_errno_app_uid(void)
{
    return susfs_is_current_proc_umounted_app();
}

/* Copy a user-space path to kernel, checking the prefix + family. Returns the
 * errno to set (or 0 when the prefix does not match or the copy fails). */
static int susfs_errno_check_path(void __user *upath, int family)
{
    char buf[SUSFS_ERRNO_MAX_PATH];
    long n;
    int pfx, ret;

    if (!susfs_errno_app_uid())
        return 0;
    if (!upath)
        return 0;

    n = strncpy_from_user(buf, upath, sizeof(buf) - 1);
    if (n < 0)
        return 0;
    buf[n] = '\0';

    pfx = susfs_errno_prefix_match(buf, n);
    if (pfx < 0)
        return 0;

    ret = susfs_errno_errno_for(pfx, family);
    if (ret)
        SUSFS_LOGI("susfs_errno: blocking %s -> %d\n", buf, ret);
    return ret;
}

/* ---- syscall wrappers ---- */

/* Each wrapper follows the same shape: check the path, return the errno if it
 * matches, otherwise call the original and return its result. The path argument
 * position and syscall family differ per syscall. */

#define SUSFS_ERRNO_WRAPPER(fn, slot, path_reg, family)			\
static __nocfi long fn(const struct pt_regs *regs)			\
{									\
    susfs_syscall_fn_t orig = READ_ONCE(slot);				\
    int en;							\
									\
    if (!orig)							\
        return -ENOSYS;						\
    en = susfs_errno_check_path(					\
        (void __user *)regs->regs[path_reg], family);		\
    if (en)							\
        return en;						\
    return orig(regs);						\
}

/* openat: regs[1] = filename */
static susfs_syscall_fn_t errno_orig_openat;
SUSFS_ERRNO_WRAPPER(errno_wrap_openat, errno_orig_openat, 1,
                    SUSFS_FAMILY_OPENAT)

/* openat2: regs[1] = filename */
static susfs_syscall_fn_t errno_orig_openat2;
SUSFS_ERRNO_WRAPPER(errno_wrap_openat2, errno_orig_openat2, 1,
                    SUSFS_FAMILY_OPENAT)

/* mkdirat: regs[1] = pathname */
static susfs_syscall_fn_t errno_orig_mkdirat;
SUSFS_ERRNO_WRAPPER(errno_wrap_mkdirat, errno_orig_mkdirat, 1,
                    SUSFS_FAMILY_MKDIRAT)

/* unlinkat: regs[1] = pathname */
static susfs_syscall_fn_t errno_orig_unlinkat;
SUSFS_ERRNO_WRAPPER(errno_wrap_unlinkat, errno_orig_unlinkat, 1,
                    SUSFS_FAMILY_UNLINKAT)

/* symlinkat: regs[2] = newname */
static susfs_syscall_fn_t errno_orig_symlinkat;
SUSFS_ERRNO_WRAPPER(errno_wrap_symlinkat, errno_orig_symlinkat, 2,
                    SUSFS_FAMILY_SYMLINKAT_NEWNAME)

/* linkat: regs[1] = oldname, regs[3] = newname; check both with their own families */
static susfs_syscall_fn_t errno_orig_linkat;
static __nocfi long errno_wrap_linkat(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(errno_orig_linkat);
    int en;
    if (!orig)
        return -ENOSYS;
    en = susfs_errno_check_path(
        (void __user *)regs->regs[1], SUSFS_FAMILY_LINKAT_OLDNAME);
    if (en)
        return en;
    en = susfs_errno_check_path(
        (void __user *)regs->regs[3], SUSFS_FAMILY_LINKAT_NEWNAME);
    if (en)
        return en;
    return orig(regs);
}

/* renameat2: regs[1] = oldname, regs[3] = newname; check both with their own families */
static susfs_syscall_fn_t errno_orig_renameat2;
static __nocfi long errno_wrap_renameat2(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(errno_orig_renameat2);
    int en;
    if (!orig)
        return -ENOSYS;
    en = susfs_errno_check_path(
        (void __user *)regs->regs[1], SUSFS_FAMILY_RENAMEAT2_OLDNAME);
    if (en)
        return en;
    en = susfs_errno_check_path(
        (void __user *)regs->regs[3], SUSFS_FAMILY_RENAMEAT2_NEWNAME);
    if (en)
        return en;
    return orig(regs);
}

/* truncate: regs[0] = pathname */
static susfs_syscall_fn_t errno_orig_truncate;
SUSFS_ERRNO_WRAPPER(errno_wrap_truncate, errno_orig_truncate, 0,
                    SUSFS_FAMILY_ALL_ENOENT)

/* faccessat: regs[1] = pathname */
static susfs_syscall_fn_t errno_orig_faccessat;
SUSFS_ERRNO_WRAPPER(errno_wrap_faccessat, errno_orig_faccessat, 1,
                    SUSFS_FAMILY_ALL_ENOENT)

/* faccessat2: regs[1] = pathname */
static susfs_syscall_fn_t errno_orig_faccessat2;
SUSFS_ERRNO_WRAPPER(errno_wrap_faccessat2, errno_orig_faccessat2, 1,
                    SUSFS_FAMILY_ALL_ENOENT)

/* chdir: regs[0] = pathname */
static susfs_syscall_fn_t errno_orig_chdir;
SUSFS_ERRNO_WRAPPER(errno_wrap_chdir, errno_orig_chdir, 0,
                    SUSFS_FAMILY_ALL_ENOENT)

/* ---- hook table ---- */
static struct susfs_fp_hook errno_hooks[] = {
    { .nr = __NR_openat,   .name = "errno/openat",
      .sym = "__arm64_sys_openat",
      .wrapper = errno_wrap_openat, .orig_slot = &errno_orig_openat },
    { .nr = __NR_openat2,  .name = "errno/openat2",
      .sym = "__arm64_sys_openat2",
      .wrapper = errno_wrap_openat2, .orig_slot = &errno_orig_openat2 },
    { .nr = __NR_mkdirat,  .name = "errno/mkdirat",
      .sym = "__arm64_sys_mkdirat",
      .wrapper = errno_wrap_mkdirat, .orig_slot = &errno_orig_mkdirat },
    { .nr = __NR_unlinkat, .name = "errno/unlinkat",
      .sym = "__arm64_sys_unlinkat",
      .wrapper = errno_wrap_unlinkat, .orig_slot = &errno_orig_unlinkat },
    { .nr = __NR_symlinkat, .name = "errno/symlinkat",
      .sym = "__arm64_sys_symlinkat",
      .wrapper = errno_wrap_symlinkat, .orig_slot = &errno_orig_symlinkat },
    { .nr = __NR_linkat,   .name = "errno/linkat",
      .sym = "__arm64_sys_linkat",
      .wrapper = errno_wrap_linkat, .orig_slot = &errno_orig_linkat },
    { .nr = __NR_renameat2, .name = "errno/renameat2",
      .sym = "__arm64_sys_renameat2",
      .wrapper = errno_wrap_renameat2, .orig_slot = &errno_orig_renameat2 },
    { .nr = __NR_truncate, .name = "errno/truncate",
      .sym = "__arm64_sys_truncate",
      .wrapper = errno_wrap_truncate, .orig_slot = &errno_orig_truncate },
    { .nr = __NR_faccessat, .name = "errno/faccessat",
      .sym = "__arm64_sys_faccessat",
      .wrapper = errno_wrap_faccessat, .orig_slot = &errno_orig_faccessat },
    { .nr = __NR_faccessat2, .name = "errno/faccessat2",
      .sym = "__arm64_sys_faccessat2",
      .wrapper = errno_wrap_faccessat2, .orig_slot = &errno_orig_faccessat2 },
    { .nr = __NR_chdir,    .name = "errno/chdir",
      .sym = "__arm64_sys_chdir",
      .wrapper = errno_wrap_chdir, .orig_slot = &errno_orig_chdir },
};

static int n_armed;

int susfs_errno_init(void)
{
	int i, rc;

	if (!errno_enable) {
		SUSFS_LOGI("susfs_errno: disabled (set errno_enable=1 to arm)\n");
		return 0;
	}

	if (susfs_fp_init())
		return 0; /* not fatal: fp hooks may be unavailable */

    for (i = 0; i < ARRAY_SIZE(errno_hooks); i++) {
        rc = susfs_fp_install(&errno_hooks[i]);
        if (!rc) {
            n_armed++;
            SUSFS_LOGI("susfs_errno: %s armed\n", errno_hooks[i].name);
        } else {
            pr_warn("susfs_errno: %s not armed (%d)\n",
                    errno_hooks[i].name, rc);
        }
    }

    if (n_armed)
        SUSFS_LOGI("susfs_errno: %d/%d hooks armed\n",
                   n_armed, (int)ARRAY_SIZE(errno_hooks));
    return 0;
}

void susfs_errno_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(errno_hooks); i++)
        susfs_fp_remove(&errno_hooks[i]);

    if (n_armed)
        susfs_fp_drain();
    n_armed = 0;
}

bool susfs_errno_active(void)
{
    return n_armed > 0;
}
