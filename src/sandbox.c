/*
 * Copyright (c) 2025 Leif Jakob <jakob@weite-welt.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>

#include "sandbox.h"

#ifdef HAVE_SECCOMP
#include <syslog.h>
#include <seccomp.h>

/* Define macro to create syscall rules */
#define ALLOW_SYSCALL(name) { SCMP_SYS(name), #name }

/* Structure to hold syscall info */
struct syscall_info {
    int num;
    const char *name;
};

/* Array of allowed syscalls */
static const struct syscall_info allowed_syscalls[] = {
    ALLOW_SYSCALL(brk),

    ALLOW_SYSCALL(pselect6),
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(recvmsg),
    ALLOW_SYSCALL(write),
    ALLOW_SYSCALL(sendto),
    ALLOW_SYSCALL(close),

    /* secure_random() for login seeds/nonces */
    ALLOW_SYSCALL(getrandom),

    ALLOW_SYSCALL(rt_sigreturn),
    ALLOW_SYSCALL(exit_group),
    /* Add more syscalls here as needed - see audit logs from kernel */
    { -1, NULL } /* end */
};

#undef ALLOW_SYSCALL

int
enable_seccomp(void)
{
    scmp_filter_ctx ctx;
    const struct syscall_info *syscall;

    // Initialize seccomp in whitelist mode - deny all by default
    ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) {
        syslog(LOG_ERR, "Failed to initialize seccomp");
        return -1;
    }

    // Add rules for each allowed syscall
    for (syscall = allowed_syscalls; syscall->num != -1; syscall++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall->num, 0) < 0) {
            syslog(LOG_ERR, "Failed to add %s rule", syscall->name);
            seccomp_release(ctx);
            return -1;
        }
    }

    // Load the rules
    if (seccomp_load(ctx) < 0) {
        syslog(LOG_ERR, "Failed to load seccomp rules");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return 0;
}
#endif
