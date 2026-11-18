/* Exercises the descriptor metadata contract without linking fsgate. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int refused(long result, int expected) {
    if (result != -1 || errno != expected) {
        fprintf(stderr, "result=%ld errno=%d expected=%d\n", result, errno, expected);
        return 1;
    }
    return 0;
}

static void interrupted(int signal) { (void)signal; }

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "ignore-sigchld") == 0) {
        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) return 26;
        execv(argv[2], &argv[2]);
        return 27;
    }
    if (argc != 3) return 2;
    if (strcmp(argv[1], "write") == 0)
        return refused(open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600), EOPNOTSUPP);
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) return 3;
    if (strcmp(argv[1], "metadata-cancel") == 0) {
        struct sigaction action = {0};
        action.sa_handler = interrupted;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, NULL) != 0) return 28;
        struct stat st;
        memset(&st, 0x5a, sizeof st);
        struct stat untouched = st;
        if (refused(syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH), EINTR)) return 29;
        if (memcmp(&st, &untouched, sizeof st) != 0) return 30;
    } else if (strcmp(argv[1], "metadata") == 0) {
        struct stat st;
        if (syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH) != 0) return 4;
        if (!S_ISREG(st.st_mode) || st.st_size != 14) return 5;
        if (syscall(SYS_newfstatat, AT_FDCWD, argv[2], &st, 0) != 0) return 23;
        if (!S_ISREG(st.st_mode) || st.st_size != 14) return 24;
        if (refused(syscall(SYS_newfstatat, fd, "relative", &st, 0), EOPNOTSUPP)) return 25;
        memset(&st, 0x5a, sizeof st);
        struct stat untouched = st;
        if (refused(syscall(SYS_newfstatat, AT_FDCWD, "/etc/passwd", &st, 0), EACCES)) return 6;
        if (memcmp(&st, &untouched, sizeof st) != 0) return 7;
        if (refused(syscall(SYS_newfstatat, fd, "", (void *)1, AT_EMPTY_PATH), EFAULT)) return 8;
        char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages == MAP_FAILED) return 9;
        memset(pages, 0x5a, 8192);
        if (mprotect(pages + 4096, 4096, PROT_READ) != 0) return 10;
        if (refused(syscall(SYS_newfstatat, fd, "", pages + 4096, AT_EMPTY_PATH), EFAULT)) return 11;
        if (refused(syscall(SYS_newfstatat, fd, "", pages + 4096 - 8, AT_EMPTY_PATH), EFAULT)) return 12;
        for (int i = 4096; i < 8192; ++i) if (pages[i] != 0x5a) return 13;
        munmap(pages, 8192);
    } else if (strcmp(argv[1], "descendants") == 0) {
        if (refused(syscall(SYS_fork), EOPNOTSUPP)) return 14;
        if (refused(syscall(SYS_vfork), EOPNOTSUPP)) return 15;
        if (refused(syscall(SYS_clone, 0, NULL, NULL, NULL, 0), EOPNOTSUPP)) return 16;
        if (refused(syscall(SYS_clone3, NULL, 0), EOPNOTSUPP)) return 17;
    } else if (strcmp(argv[1], "revoke") == 0) {
        char signal;
        if (read(STDIN_FILENO, &signal, 1) != 1) return 18;
        if (refused(open(argv[2], O_RDONLY), EACCES)) return 19;
        char content[14];
        if (read(fd, content, sizeof content) != sizeof content) return 20;
        if (memcmp(content, "hello runtime\n", sizeof content) != 0) return 21;
    } else return 22;
    close(fd);
    puts("ok");
    return 0;
}
