/*
 * Worker fixture for the RFC 0004 probe. Built with `cc -static`, so it has
 * no PT_INTERP and does not link fsgate: every open below is an ordinary libc
 * call or a raw syscall that the supervisor sees only through seccomp.
 *
 * Usage: worker <op> [path] [resolve]
 * On success an op prints what it read; on failure it prints `errno=N` and
 * exits 3.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* `struct open_how` from linux/openat2.h, redeclared to avoid clashing
 * with libc headers that define it too. */
struct probe_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

static int fail(void) {
    printf("errno=%d\n", errno);
    return 3;
}

static int dump(int fd) {
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        fwrite(buf, 1, (size_t)n, stdout);
    }
    return n < 0 ? fail() : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: worker <op> [path] [resolve]\n");
        return 2;
    }
    const char *op = argv[1];
    const char *path = argc > 2 ? argv[2] : "";

    if (strcmp(op, "read") == 0) {
        int fd = open(path, O_RDONLY);
        return fd < 0 ? fail() : dump(fd);
    }
    if (strcmp(op, "write") == 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return fail();
        printf("opened for writing\n");
        return 0;
    }
    if (strcmp(op, "creat") == 0) {
        /* Not a notified syscall: only Landlock stands in the way. */
        long fd = syscall(SYS_creat, path, 0644);
        if (fd < 0) return fail();
        printf("created\n");
        return 0;
    }
    if (strcmp(op, "openat2") == 0) {
        struct probe_open_how how = {0};
        how.flags = O_RDONLY;
        how.resolve = argc > 3 ? strtoull(argv[3], NULL, 0) : 0;
        long fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof how);
        return fd < 0 ? fail() : dump((int)fd);
    }
    if (strcmp(op, "cloexec") == 0) {
        int plain = open(path, O_RDONLY);
        int marked = open(path, O_RDONLY | O_CLOEXEC);
        if (plain < 0 || marked < 0) return fail();
        printf("plain=%d marked=%d\n",
               (fcntl(plain, F_GETFD) & FD_CLOEXEC) != 0,
               (fcntl(marked, F_GETFD) & FD_CLOEXEC) != 0);
        return 0;
    }
    if (strcmp(op, "fds") == 0) {
        for (int fd = 3; fd < 1024; fd++) {
            if (fcntl(fd, F_GETFD) != -1) printf("open=%d\n", fd);
        }
        printf("done\n");
        return 0;
    }
    fprintf(stderr, "unknown op: %s\n", op);
    return 2;
}
