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

#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "common.h"
#include "sandbox.h"
#include "test.h"

#ifdef HAVE_SECCOMP
/* Run fn in a child with the iodined filter loaded, return its wait status */
static int
run_sandboxed(void (*fn)(void))
{
	int status;
	pid_t pid;

	pid = fork();
	fail_if(pid < 0, "fork failed");
	if (pid == 0) {
		if (enable_seccomp() < 0)
			_exit(2);
		fn();
		_exit(0);
	}
	fail_if(waitpid(pid, &status, 0) != pid, "waitpid failed");
	return status;
}

static void
do_secure_random(void)
{
	char buf[16];

	secure_random(buf, sizeof(buf));
}

static void
do_getpid(void)
{
	getpid();
}

START_TEST(test_sandbox_allows_secure_random)
{
	int status = run_sandboxed(do_secure_random);

	ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"secure_random() under seccomp: status 0x%x", status);
}
END_TEST

START_TEST(test_sandbox_blocks_other_syscalls)
{
	int status = run_sandboxed(do_getpid);

	ck_assert_msg(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS,
		"getpid() under seccomp: status 0x%x", status);
}
END_TEST
#endif

TCase *
test_sandbox_create_tests(void)
{
	TCase *tc;

	tc = tcase_create("Sandbox");
#ifdef HAVE_SECCOMP
	tcase_add_test(tc, test_sandbox_allows_secure_random);
	tcase_add_test(tc, test_sandbox_blocks_other_syscalls);
#endif

	return tc;
}
