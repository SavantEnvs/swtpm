/*
 * Fuzz swtpm's control channel protocol (--ctrl type=unixio,...), the channel QEMU and
 * swtpm_ioctl drive: CMD_INIT, STOP, SET_LOCALITY, HASH_START/DATA/END, GET/SET_STATEBLOB, SET_BUFFERSIZE,
 * GET_INFO, LOCK_STORAGE, ... are parsed by ctrlchannel_process_fd() (ctrlchannel.c) and executed
 * against libtpms through tpmlib.c and the NV store (swtpm_nvstore*.c, tlv.c, swtpm_aes.c).
 *
 * Input: a sequence of control messages, each prefixed by a 2-byte big-endian length (at most
 * MAX_MSGS). They are sent as packets on an AF_UNIX SOCK_SEQPACKET socketpair (the ctrl channel
 * reads one command per recvmsg), the sending side is shut down, and ctrlchannel_process_fd()
 * runs until it reports EOF/error or a CMD_SHUTDOWN.
 *
 * State reset per input: the TPM is terminated, the dir:// state directory is emptied, the
 * libtpms buffer size is restored and the main loop parameters/locality are re-initialised.
 */
#include "config.h"

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <glib.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_nvfilename.h>

#include "fuzz_common.h"
#include "common.h"
#include "ctrlchannel.h"
#include "logging.h"
#include "mainloop.h"
#include "swtpm_io.h"
#include "swtpm_nvstore.h"
#include "tpmlib.h"
#include "tpmstate.h"

#define MAX_MSGS 64

static char g_dir[PATH_MAX];
static uint32_t g_bufsize;

static struct libtpms_callbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init          = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata     = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = SWTPM_IO_Init,
    .tpm_io_getlocality      = mainloop_cb_get_locality,
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

static void drain(int fd)
{
    char buf[4096];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
        ;
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
    /* swtpm has the NV backend selected before any control command can unlock storage */
    if (SWTPM_NVRAM_Init() != TPM_SUCCESS)
        abort();
    /* the buffer size libtpms starts with; CMD_SET_BUFFERSIZE changes it process-wide */
    g_bufsize = TPMLIB_SetBufferSize(0, NULL, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mainLoopParams mlp = {
        .fd = -1,
        .tpmversion = TPMLIB_TPM_VERSION_2,
        .locking_retries = 0,
    };
    TPM_MODIFIER_INDICATOR locality = 0;
    bool terminate = false, tpm_running = false;
    int sv[2], nmsgs = 0;
    size_t off = 0;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0)
        abort();
    /* server side non-blocking: a missing continuation chunk ends with EOF, never a wait */
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);

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

    while (!terminate) {
        int r = ctrlchannel_process_fd(sv[1], &terminate, &locality,
                                       &tpm_running, &mlp);
        drain(sv[0]);
        if (r < 0)
            break; /* ctrlchannel_process_fd() closed sv[1] */
    }
    if (terminate)
        close(sv[1]);
    close(sv[0]);
    if (mlp.fd >= 0)
        close(mlp.fd);

    /* reset everything the commands could change */
    TPMLIB_Terminate();
    SWTPM_NVRAM_Unlock();
    SWTPM_NVRAM_Shutdown();
    g_free(mlp.json_profile);
    TPMLIB_SetBufferSize(g_bufsize, NULL, NULL);
    empty_dir(g_dir);
    return 0;
}
