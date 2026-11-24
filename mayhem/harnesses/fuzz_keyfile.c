/*
 * Fuzz swtpm's state-encryption key options and the key / passphrase files they name:
 * handle_key_options() (--key) and handle_migration_key_options() (--migration-key) in
 * src/swtpm/common.c, i.e. parse_key_options() with its format=/mode=/kdf=/remove= values, and
 * the readers in src/swtpm/key.c (key_load_key_fd(): hex or binary key; key_from_pwdfile_fd():
 * sha512 or pbkdf2 KDF over a passphrase), then SWTPM_NVRAM_Set_FileKey/_MigrationKey().
 *
 * Input: byte 0 selects --key (bit 0 clear) or --migration-key (bit 0 set), and whether the file
 * is a key file, fd= (bit 1 clear), or a passphrase file, pwdfd= (bit 1 set). The rest is
 * "<option string>\0<file content>" (no NUL: empty option string, all of it is the file).
 * The file is a memfd; the harness passes it as the FIRST fd=/pwdfd= option, which
 * option_get_int() picks (it returns the first match), exactly as `swtpm --key fd=N,...` does.
 *
 * The harness owns which file is read: an option string containing "file" (file=, pwdfile=) or
 * "fd" (fd=, pwdfd=) is rejected, since those would open a path the fuzzer names or read/close
 * one of the fuzzer's own fds. options_parse() splits on ',' and '=' with no unescaping
 * (src/swtpm/options.c), so the substring test covers every way to spell those keys.
 *
 * State: parse_key_options() closes the memfd; the keys it stores in swtpm_nvstore.c's globals
 * are zeroed after each input by SWTPM_NVRAM_Shutdown() (no backend is set, so that is all it does).
 */
#include "config.h"

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "fuzz_common.h"
#include "common.h"
#include "logging.h"
#include "swtpm_nvstore.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    log_init_fd(SUPPRESS_LOGGING);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *nul, *content;
    size_t optlen, clen;
    char *opts, *full;
    uint8_t sel;
    int fd;

    if (size < 1)
        return -1;
    sel = data[0];
    data++;
    size--;

    nul = memchr(data, 0, size);
    if (nul) {
        optlen = (size_t)(nul - data);
        content = nul + 1;
        clen = size - optlen - 1;
    } else {
        optlen = 0;
        content = data;
        clen = size;
    }
    opts = strndup((const char *)data, optlen);
    if (!opts)
        abort();
    if (strstr(opts, "file") || strstr(opts, "fd")) {
        free(opts);
        return -1;
    }

    fd = memfd_create("swtpm-fuzz-key", 0);
    if (fd < 0)
        abort();
    if (clen && write(fd, content, clen) != (ssize_t)clen)
        abort();
    lseek(fd, 0, SEEK_SET);

    if (asprintf(&full, "%s=%d%s%s", (sel & 2) ? "pwdfd" : "fd", fd,
                 optlen ? "," : "", opts) < 0)
        abort();

    if (sel & 1)
        handle_migration_key_options(full);
    else
        handle_key_options(full);

    /* parse_key_options() closes the fd only once it got that far; close it if it is still ours */
    if (fcntl(fd, F_GETFD) != -1)
        close(fd);

    SWTPM_NVRAM_Shutdown();
    free(full);
    free(opts);
    return 0;
}
