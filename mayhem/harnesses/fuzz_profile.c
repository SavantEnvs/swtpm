/*
 * Fuzz the TPM 2 profile swtpm accepts with `--profile fd=N[,remove-disabled=check|fips-host]`
 * (also file=/profile=): handle_profile_options() in common.c reads the JSON and, with
 * remove-disabled, profile_remove_fips_disabled_algorithms() (profile.c) walks and rewrites it
 * with the json-glib helpers in utils.c and the algorithm checks in check_algos.c.
 *
 * Input: byte 0 selects remove-disabled (0: none, 1: check, 2+: fips-host); the rest is the
 * profile, delivered through a memfd exactly as `fd=` reads it.
 */
#include "config.h"

#define _GNU_SOURCE
#include <stdint.h>
#include <sys/mman.h>

#include <glib.h>

#include "fuzz_common.h"
#include "common.h"
#include "logging.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_quiet_stdout();
    log_init_fd(SUPPRESS_LOGGING);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *modes[] = { "", ",remove-disabled=check", ",remove-disabled=fips-host" };
    char opts[128];
    char *json = NULL;
    uint8_t sel;
    int fd;

    if (size < 1)
        return -1;
    sel = data[0] > 2 ? 2 : data[0];
    data++;
    size--;

    fd = memfd_create("swtpm-fuzz-profile", 0);
    if (fd < 0)
        abort();
    if (size && write(fd, data, size) != (ssize_t)size)
        abort();
    lseek(fd, 0, SEEK_SET);

    snprintf(opts, sizeof(opts), "fd=%d%s", fd, modes[sel]);
    handle_profile_options(opts, &json); /* closes fd on the read path */
    g_free(json);
    close(fd); /* EBADF when handle_profile_options() already closed it */
    return 0;
}
