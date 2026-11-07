/*
 * Worker fixture for the RFC 0004 launcher tests. Built with `cc -static`, so it has
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
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* The launcher moves the worker image to this descriptor number before the
 * allowlist; tests aim reused descriptors and paths at it. */
#define RESERVED_IMAGE_FD 1000

/* `struct open_how` from linux/openat2.h, redeclared to avoid clashing
 * with libc headers that define it too. */
struct worker_open_how {
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

static void *read_in_thread(void *path) {
    int fd = open(path, O_RDONLY);
    return (void *)(intptr_t)(fd < 0 ? fail() : dump(fd));
}

/* Shared by the `race` op: one thread rewrites `race_path` between two
 * paths while the main thread keeps opening it. */
static char race_path[4096];
static const char *race_paths[2];
static atomic_int race_stop;

static void *flip_race_path(void *unused) {
    (void)unused;
    size_t first = strlen(race_paths[0]) + 1;
    size_t second = strlen(race_paths[1]) + 1;
    while (!atomic_load(&race_stop)) {
        memcpy(race_path, race_paths[0], first);
        memcpy(race_path, race_paths[1], second);
    }
    return NULL;
}

static int run_execveat(int dirfd, const char *path) {
    char *args[] = {"worker", "fds", NULL};
    char *env[] = {NULL};
    syscall(SYS_execveat, dirfd, path, args, env, AT_EMPTY_PATH);
    return fail();
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
    if (strcmp(op, "raw-open") == 0) {
        /* The `open` syscall itself; glibc's open() uses openat. */
        long fd = syscall(SYS_open, path, O_RDONLY);
        return fd < 0 ? fail() : dump((int)fd);
    }
    if (strcmp(op, "race") == 0) {
        /* race <granted> <secret> <rounds>: never read the secret. */
        if (argc < 5) return 2;
        race_paths[0] = path;
        race_paths[1] = argv[3];
        int rounds = atoi(argv[4]);
        memcpy(race_path, path, strlen(path) + 1);
        pthread_t flipper;
        if (pthread_create(&flipper, NULL, flip_race_path, NULL) != 0) return 4;
        int granted = 0, denied = 0;
        for (int round = 0; round < rounds; round++) {
            long fd = syscall(SYS_openat, AT_FDCWD, race_path, O_RDONLY);
            if (fd < 0) {
                denied++;
                continue;
            }
            char buf[16] = {0};
            ssize_t n = read((int)fd, buf, sizeof buf - 1);
            close((int)fd);
            if (n > 0 && strncmp(buf, "secret", 6) == 0) {
                atomic_store(&race_stop, 1);
                printf("LEAK\n");
                return 1;
            }
            granted++;
        }
        atomic_store(&race_stop, 1);
        pthread_join(flipper, NULL);
        printf("ok granted=%d denied=%d\n", granted, denied);
        return 0;
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
        struct worker_open_how how = {0};
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
    if (strcmp(op, "exec") == 0) {
        char *args[] = {(char *)path, NULL};
        char *env[] = {NULL};
        execve(path, args, env);
        return fail();
    }
    if (strcmp(op, "execfd") == 0) {
        /* Reuse the reserved number for a delivered file, then exec it. */
        int fd = open(path, O_RDONLY);
        if (fd < 0 || dup2(fd, RESERVED_IMAGE_FD) < 0) return fail();
        return run_execveat(RESERVED_IMAGE_FD, "");
    }
    if (strcmp(op, "execat") == 0) {
        /* An absolute path is resolved without the directory descriptor. */
        return run_execveat(RESERVED_IMAGE_FD, path);
    }
    if (strcmp(op, "uring") == 0) {
        char params[120] = {0};
        if (syscall(SYS_io_uring_setup, 1, params) < 0) return fail();
        printf("io_uring\n");
        return 0;
    }
    if (strcmp(op, "socket") == 0) {
        if (socket(AF_UNIX, SOCK_STREAM, 0) < 0) return fail();
        printf("socket\n");
        return 0;
    }
    if (strcmp(op, "prctl") == 0) {
        if (prctl(PR_SET_NAME, "renamed", 0, 0, 0) < 0) return fail();
        printf("renamed\n");
        return 0;
    }
    if (strcmp(op, "clone-ns") == 0) {
        long pid = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
        if (pid < 0) return fail();
        if (pid == 0) _exit(0);
        printf("cloned\n");
        return 0;
    }
    if (strcmp(op, "fork-read") == 0) {
        pid_t pid = fork();
        if (pid < 0) return fail();
        if (pid == 0) {
            int fd = open(path, O_RDONLY);
            int code = fd < 0 ? fail() : dump(fd);
            fflush(stdout);
            _exit(code);
        }
        int status;
        if (waitpid(pid, &status, 0) < 0) return fail();
        return WIFEXITED(status) ? WEXITSTATUS(status) : 4;
    }
    if (strcmp(op, "thread-read") == 0) {
        pthread_t thread;
        void *code;
        if (pthread_create(&thread, NULL, read_in_thread, (void *)path) != 0) {
            printf("pthread_create failed\n");
            return 4;
        }
        pthread_join(thread, &code);
        return (int)(intptr_t)code;
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
