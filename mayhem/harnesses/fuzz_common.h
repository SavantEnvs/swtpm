/* Shared helpers for the swtpm fuzz harnesses (mayhem/harnesses). */
#ifndef SWTPM_FUZZ_COMMON_H
#define SWTPM_FUZZ_COMMON_H
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Create a private scratch directory under $TMPDIR (fallback /tmp). */
static inline void fuzz_mkscratch(char *out, size_t outlen)
{
    const char *t = getenv("TMPDIR");
    if (!t || !*t)
        t = "/tmp";
    snprintf(out, outlen, "%s/swtpm-fuzz-XXXXXX", t);
    if (!mkdtemp(out)) {
        perror("mkdtemp");
        abort();
    }
}

/* Replace the file at path with exactly data[0..size). */
static inline void fuzz_write_file(const char *path, const unsigned char *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open");
        abort();
    }
    while (size > 0) {
        ssize_t n = write(fd, data, size);
        if (n <= 0) {
            perror("write");
            abort();
        }
        data += n;
        size -= (size_t)n;
    }
    close(fd);
}

/* swtpm logs to stderr/stdout; keep the fuzzer output readable. */
static inline void fuzz_quiet_stdout(void)
{
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }
}
#endif
