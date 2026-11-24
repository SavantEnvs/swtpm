/*
 * Fuzz swtpm_setup's configuration file (swtpm_setup.conf, e.g. ~/.config/swtpm_setup.conf or
 * `swtpm_setup --config <file>`) and the TPM 2 profile it names, the way swtpm_setup's main()
 * consumes them:
 *  - read_file_lines() (src/utils/swtpm_utils.c) splits the file into lines;
 *  - get_config_value() (src/swtpm_setup/swtpm_setup_utils.c: regex match, then resolve_string()
 *    expands ${ENV} references) reads every key swtpm_setup reads: create_certs_tool,
 *    create_certs_tool_config, create_certs_tool_options, active_pcr_banks, rsa_keysize,
 *    profile_file, local_profiles_dir and profile;
 *  - the `profile = <json>` value (get_default_profile() in swtpm_setup.c: get_config_value() +
 *    g_strstrip()) goes to check_json_profile() (src/swtpm_setup/profile.c), as
 *    validate_json_profile() does, which uses json_get_map_value()/strv_strcmp(), and to
 *    profile_name_check().
 * If the input holds a NUL byte, the config file is the part before it and the part after it is
 * the `--profile-name <name>` argument: then, as in main(), profile_name_check() and
 * profile_get_by_name() (local_profiles_dir from the config, the distro dir, or a builtin:
 * name turned into {"Name":...}) run instead of reading the config's default profile, and a
 * builtin profile's JSON goes to check_json_profile(). A profile file that is found is only
 * opened by swtpm later, so it is not read here.
 * The capabilities JSON check_json_profile() compares against is what swtpm_setup gets from
 * `swtpm --print-capabilities`, i.e. from swtpm itself, so it is not fuzzed: CAPS below is the
 * output of the swtpm built here.
 *
 * State: the config file is rewritten for every input in a private scratch dir; nothing else is kept.
 */
#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "fuzz_common.h"
#include "profile.h"
#include "swtpm_setup_utils.h"
#include "swtpm_utils.h"

gchar *gl_LOGFILE = NULL; /* swtpm_setup.c's global: log to stderr */

static const char CAPS[] = "{ \"type\": \"swtpm\", \"features\": [ \"tpm-2.0\", \"tpm-send-command-header\", \"flags-opt-startup\", \"flags-opt-disable-auto-shutdown\", \"ctrl-opt-terminate\", \"cmdarg-key-fd\", \"cmdarg-pwd-fd\", \"cmdarg-print-states\", \"cmdarg-chroot\", \"cmdarg-migration\", \"nvram-backend-dir\", \"nvram-backend-file\", \"rsa-keysize-1024\", \"rsa-keysize-2048\", \"rsa-keysize-3072\", \"rsa-keysize-4096\", \"cmdarg-profile\", \"cmdarg-print-profiles\", \"profile-opt-remove-disabled\", \"cmdarg-print-info\", \"tpmstate-opt-lock\", \"tpmstate-dir-backend-opt-backup\", \"tpmstate-dir-backend-opt-fsync\", \"cmdarg-pcap\", \"systemd-notify\" ], \"profiles\": { \"names\": [ \"default-v2\", \"default-v1\", \"null\", \"custom\" ], \"algorithms\": { \"canbedisabled\": \"tdes,sha1,sha512,rsassa,rsaes,rsapss,ecdaa,sm2,ecschnorr,ecmqv,ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,camellia,cmac,ctr,ofb,cbc,ecb\", \"implemented\": \"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,hmac-min-key-size=1,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb\" }, \"commands\": { \"canbedisabled\": \"0x11f,0x121-0x122,0x124-0x128,0x12a,0x12c-0x12e,0x130,0x132-0x13b,0x13d-0x140,0x142,0x146-0x147,0x149-0x14d,0x14f-0x152,0x154-0x155,0x159,0x15b,0x15d-0x15e,0x160-0x164,0x167-0x168,0x16a-0x172,0x174,0x177-0x178,0x17b,0x17f-0x181,0x183-0x184,0x187-0x193,0x197,0x199-0x19c\", \"implemented\": \"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c\" } }, \"version\": \"0.11.0\" }";

static char conf_path[PATH_MAX];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char dir[PATH_MAX];

    (void)argc; (void)argv;
    fuzz_mkscratch(dir, sizeof(dir));
    snprintf(conf_path, sizeof(conf_path), "%s/swtpm_setup.conf", dir);
    return 0;
}

static const char *const KEYS[] = {
    "create_certs_tool", "create_certs_tool_config", "create_certs_tool_options",
    "active_pcr_banks", "rsa_keysize", "profile_file", "local_profiles_dir",
};

static void validate_json_profile(const gchar *json_profile)
{
    gchar **names = NULL;

    check_json_profile(CAPS, json_profile);
    if (get_profile_names(CAPS, &names) == 0)
        g_strfreev(names);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *nul = memchr(data, 0, size);
    size_t conflen = nul ? (size_t)(nul - data) : size;
    gchar **lines = NULL;
    gchar *profile = NULL, *profile_file = NULL, *name = NULL;
    size_t i;

    fuzz_write_file(conf_path, data, conflen);
    if (read_file_lines(conf_path, &lines) != 0)
        abort(); /* the file was just written */

    for (i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++)
        g_free(get_config_value(lines, KEYS[i]));

    if (nul) {
        /* --profile-name <name>: a command-line argument, so it ends at the next NUL */
        name = g_strndup((const gchar *)nul + 1, size - conflen - 1);
        if (profile_name_check(name) == 0 &&
            profile_get_by_name(lines, name, &profile_file, &profile) == 0 && profile)
            validate_json_profile(profile);
    } else {
        /* get_default_profile() */
        profile = get_config_value(lines, "profile");
        if (profile) {
            g_strstrip(profile);
            validate_json_profile(profile);
        }
    }

    g_free(profile);
    g_free(profile_file);
    g_free(name);
    g_strfreev(lines);
    return 0;
}
