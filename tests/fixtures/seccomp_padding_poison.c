#define _GNU_SOURCE

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void die(const char *message) {
    perror(message);
    _exit(1);
}

int main(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program;

    memset(&program, 0x41, sizeof(program));
    program.len = (unsigned short)(sizeof(filter) / sizeof(filter[0]));
    program.filter = filter;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        die("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        die("seccomp(SECCOMP_SET_MODE_FILTER)");
    }

    puts("installed poisoned padding");
    return 0;
}
