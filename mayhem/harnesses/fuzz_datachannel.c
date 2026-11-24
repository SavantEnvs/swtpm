/*
 * Fuzz swtpm's TPM command data channel: mainLoop() (mainloop.c) reads each TPM request from
 * the client fd (swtpm_io.c), strips the optional TCG TPM2_SEND_COMMAND prefix (locality),
 * handles swtpm's own commands (tpmlib_process(): locality, cancel, vendor commands) and passes
 * the rest to libtpms' TPMLIB_Process(), as `swtpm socket --tpm2 --server type=unixio,...`
 * or `swtpm chardev` does for every request a guest sends.
 *
 * Input: a sequence of TPM requests, each prefixed by a 2-byte big-endian length (at most
 * MAX_MSGS), sent as packets on an AF_UNIX SOCK_SEQPACKET socketpair (one read() per request,
 * like the chardev/vTPM proxy), after which the sending side is shut down. The TPM is started
 * on a fresh state directory and TPM2_Startup(CLEAR) is sent by mainLoop() first
 * (--flags startup-clear).
 *
 * State reset per input: fresh TPM (state dir emptied, libtpms terminated), main loop flags
 * re-initialised, and the harness's first request (a TPM2_SEND_COMMAND-wrapped GetRandom at
 * locality 0) resets mainloop.c's static locality, which an earlier input may have changed.
 */
#include "config.h"

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

#include "fuzz_common.h"
#include "common.h"
#include "logging.h"
#include "mainloop.h"
#include "swtpm_io.h"
#include "swtpm_nvstore.h"
#include "tpmlib.h"
#include "tpmstate.h"

#define MAX_MSGS 64

extern bool g_mainloop_terminate;

static char g_dir[PATH_MAX];

static struct libtpms_callbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init          = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata     = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = SWTPM_IO_Init,
    .tpm_io_getlocality      = mainloop_cb_get_locality,
};

/* TPM2_SEND_COMMAND prefix, locality 0, wrapping TPM2_GetRandom(8) */
static const uint8_t reset_locality[] = {
    0x00, 0x00, 0x00, 0x08,  0x00,  0x00, 0x00, 0x00, 0x0c,
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08,
};

static void empty_dir(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    char p[PATH_MAX * 2];

    if (!d)
        abort();
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
        unlink(p);
    }
    closedir(d);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char opt[PATH_MAX + 64];
    (void)argc; (void)argv;

    fuzz_mkscratch(g_dir, sizeof(g_dir));
    fuzz_quiet_stdout();
    log_init_fd(SUPPRESS_LOGGING);
    if (tpmlib_choose_tpm_version(TPMLIB_TPM_VERSION_2) != TPM_SUCCESS)
        abort();
    tpmstate_set_version(TPMLIB_TPM_VERSION_2);
    snprintf(opt, sizeof(opt), "dir=%s", g_dir);
    if (handle_tpmstate_options(opt) < 0)
        abort();
    if (tpmlib_register_callbacks(&callbacks) != TPM_SUCCESS)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mainLoopParams mlp = {
        .flags = MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD |
                 MAIN_LOOP_FLAG_KEEP_CONNECTION,
        .tpmversion = TPMLIB_TPM_VERSION_2,
        .startupType = TPM_ST_CLEAR,
        .disable_auto_shutdown = true,
        .storage_locked = true,
    };
    int sv[2], nmsgs = 0;
    size_t off = 0;

    if (tpmlib_start(0, TPMLIB_TPM_VERSION_2, false, NULL) != TPM_SUCCESS)
        abort();

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0)
        abort();
    /* server side non-blocking: never wait on a response the harness has not drained */
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);

    send(sv[0], reset_locality, sizeof(reset_locality), MSG_DONTWAIT | MSG_NOSIGNAL);
    while (off + 2 <= size && nmsgs < MAX_MSGS) {
        size_t len = ((size_t)data[off] << 8) | data[off + 1];
        off += 2;
        if (len > size - off)
            len = size - off;
        if (send(sv[0], data + off, len, MSG_DONTWAIT | MSG_NOSIGNAL) < 0)
            break;
        off += len;
        nmsgs++;
    }
    shutdown(sv[0], SHUT_WR);

    mlp.fd = sv[1];
    g_mainloop_terminate = false;
    mainLoop(&mlp, -1, true); /* closes sv[1] */
    close(sv[0]);

    TPMLIB_Terminate();
    SWTPM_NVRAM_Shutdown();
    empty_dir(g_dir);
    return 0;
}
