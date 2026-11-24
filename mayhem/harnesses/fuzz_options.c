/*
 * Fuzz swtpm's command-line option-string parsing: the comma-separated key=value tokenizer and
 * typed getters in options.c behind the values of --tpmstate, --flags, --locality and
 * --migration (handle_*_options() in common.c).
 *
 * Input: byte 0 selects the option, the rest is its value string (NUL-terminated copy).
 * Option handlers that open, create or unlink files or sockets, or read/close a caller-named fd
 * (--key/--migration-key with remove/fd=, --log, --pid, --ctrl, --server, --pcap, --profile fd=)
 * are not fuzzed here: their input is a file the key/profile targets already cover.
 *
 * State: the tpmstate globals an input can set are restored to swtpm's defaults after each run.
 */
#include "config.h"

#include <stdbool.h>
#include <stdint.h>

#include <libtpms/tpm_library.h>

#include "fuzz_common.h"
#include "common.h"
#include "logging.h"
#include "tpmstate.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_quiet_stdout();
    log_init_fd(SUPPRESS_LOGGING);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    bool b1 = false, b2 = false;
    uint16_t startup = 0;
    uint32_t flags = 0;
    char *opts;

    if (size < 1)
        return -1;
    opts = malloc(size);
    if (!opts)
        abort();
    memcpy(opts, data + 1, size - 1);
    opts[size - 1] = 0;

    switch (data[0] % 4) {
    case 0:
        tpmstate_set_version(TPMLIB_TPM_VERSION_2);
        handle_tpmstate_options(opts);
        break;
    case 1:
        handle_flags_options(opts, &b1, &startup, &b2);
        break;
    case 2:
        handle_locality_options(opts, &flags);
        break;
    case 3:
        handle_migration_options(opts, &b1, &b2);
        break;
    }
    free(opts);

    /* tpmstate.c defaults */
    tpmstate_global_free();
    tpmstate_set_mode(0640, true);
    tpmstate_set_locking(true);
    tpmstate_set_make_backup(false);
    tpmstate_set_do_fsync(false);
    tpmstate_set_version(TPMLIB_TPM_VERSION_1_2);
    return 0;
}
