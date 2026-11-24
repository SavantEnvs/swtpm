/*
 * Fuzz a per-blob TPM state file of the dir:// backend (tpm2-00.permall), as swtpm loads it
 * at TPM start (SWTPM_NVRAM_LoadData) and as it accepts it over the control channel / CUSE
 * (SWTPM_NVRAM_SetStateBlob, CMD_SET_STATEBLOB).
 *
 * Input: byte 0 selects options, the rest is the blob.
 *   bit0: a 128-bit state file key is configured (--key), so the blob is decrypted / HMAC-checked
 *   bit1: a migration key is configured (--migration-key)
 *   bit2: SetStateBlob is told the blob is encrypted
 * Reaches SWTPM_NVRAM_CheckHeader(), the TLV walk (tlv.c), swtpm_aes.c and swtpm_nvstore_dir.c.
 *
 * State: the backend URI is set once; keys are reset by SWTPM_NVRAM_Shutdown() and the blob
 * file is rewritten from the input on every run.
 */
#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_nvfilename.h>

#include "fuzz_common.h"
#include "common.h"
#include "key.h"
#include "logging.h"
#include "swtpm_nvstore.h"
#include "tpmstate.h"
#include "swtpm/tpm_ioctl.h"

static char g_path[PATH_MAX];

static const unsigned char filekey[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
static const unsigned char migkey[16] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char dir[PATH_MAX], opt[PATH_MAX + 64];
    (void)argc; (void)argv;

    fuzz_mkscratch(dir, sizeof(dir));
    snprintf(g_path, sizeof(g_path), "%s/tpm2-00.permall", dir);
    fuzz_quiet_stdout();
    log_init_fd(SUPPRESS_LOGGING);
    tpmstate_set_version(TPMLIB_TPM_VERSION_2);
    snprintf(opt, sizeof(opt), "dir=%s", dir);
    if (handle_tpmstate_options(opt) < 0)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    unsigned char *blob = NULL, *copy;
    uint32_t len = 0;
    uint8_t flags;

    if (size < 1)
        return -1;
    flags = data[0];
    data++;
    size--;

    fuzz_write_file(g_path, data, size);

    if (SWTPM_NVRAM_Init() != TPM_SUCCESS)
        abort();
    if (flags & 1)
        SWTPM_NVRAM_Set_FileKey(filekey, sizeof(filekey), ENCRYPTION_MODE_AES_CBC);
    if (flags & 2)
        SWTPM_NVRAM_Set_MigrationKey(migkey, sizeof(migkey), ENCRYPTION_MODE_AES_CBC);

    if (SWTPM_NVRAM_LoadData(&blob, &len, 0, TPM_PERMANENT_ALL_NAME) == TPM_SUCCESS)
        free(blob);

    copy = malloc(size ? size : 1);
    if (!copy)
        abort();
    memcpy(copy, data, size);
    SWTPM_NVRAM_SetStateBlob(copy, (uint32_t)size, (flags & 4) != 0, 0,
                             PTM_BLOB_TYPE_PERMANENT);
    free(copy);

    SWTPM_NVRAM_Shutdown();
    return 0;
}
