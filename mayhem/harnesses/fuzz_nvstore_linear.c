/*
 * Fuzz the linear NV store file format (backend-uri=file://...), the format swtpm reads
 * with `swtpm socket --tpm2 --tpmstate backend-uri=file://FILE --print-states` and when
 * it loads TPM state from a linear file. The input is the whole store file.
 *
 * Reaches swtpm_nvstore_linear.c (header and file-table offset/length validation),
 * swtpm_nvstore_linear_file.c, and for each stored blob SWTPM_NVRAM_CheckHeader() and the
 * TLV walk in swtpm_nvstore.c / tlv.c.
 *
 * State: the backend URI (fixed path in a private scratch dir) is set once; the file is
 * rewritten from the input and the store is shut down at the end of every input.
 */
#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_nvfilename.h>

#include "fuzz_common.h"
#include "common.h"
#include "logging.h"
#include "swtpm_nvstore.h"
#include "tpmstate.h"

static char g_path[PATH_MAX];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char dir[PATH_MAX], opt[PATH_MAX + 64];
    (void)argc; (void)argv;

    fuzz_mkscratch(dir, sizeof(dir));
    snprintf(g_path, sizeof(g_path), "%s/linear.bin", dir);
    fuzz_quiet_stdout();
    log_init_fd(SUPPRESS_LOGGING);
    tpmstate_set_version(TPMLIB_TPM_VERSION_2);
    snprintf(opt, sizeof(opt), "backend-uri=file://%s", g_path);
    if (handle_tpmstate_options(opt) < 0)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *names[] = {
        TPM_PERMANENT_ALL_NAME, TPM_VOLATILESTATE_NAME, TPM_SAVESTATE_NAME,
    };
    size_t i;

    fuzz_write_file(g_path, data, size);

    /* what --print-states does */
    SWTPM_NVRAM_PrintJson();
    SWTPM_NVRAM_Shutdown();

    /* what libtpms' nvram_loaddata callback does at TPM start */
    if (SWTPM_NVRAM_Init() == TPM_SUCCESS) {
        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            unsigned char *blob = NULL;
            uint32_t len = 0;
            if (SWTPM_NVRAM_LoadData(&blob, &len, 0, names[i]) == TPM_SUCCESS)
                free(blob);
        }
    }
    SWTPM_NVRAM_Shutdown();
    return 0;
}
