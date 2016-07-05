/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <unistd.h>
#include <string.h>

struct options {
    const char *out;
    const char *in;
    json_t *jwks;
    bool nonint;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;
    case 'n': opts->nonint = true; return 0;

    case ARGP_KEY_ARG:
        if (!opts->jwks)
            opts->jwks = json_array();

        if (json_array_append_new(opts->jwks,
                                  jcmd_load(arg, arg, NULL)) == -1) {
            fprintf(stderr, "Invalid JWK: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

    case ARGP_KEY_FINI:
        if (json_array_size(opts->jwks) == 0 && opts->nonint) {
            fprintf(stderr, "MUST specify a JWK in non-interactive mode!\n\n");
            argp_usage(state);
            return ARGP_ERR_UNKNOWN;
        }

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

static const struct argp argp = {
    .options = (const struct argp_option[]) {
        { "input", 'i', "filename", .doc = "JWE input file" },
        { "output", 'o', "filename", .doc = "JWE output file" },
        { "no-prompt", 'n', .doc = "Do not prompt for a password" },
        {}
    },
    .parser = parser,
    .args_doc = "JWK [JWK ...]",
    .doc =
  "\nDecrypts a JWE and outputs the plaintext.\n"
  "\vHere are some examples. First, we encrypt a message with two keys:\n"
  "\n    $ echo hi | jose enc -o /tmp/greeting.jws rsa.jwk oct.jwk"
  "\n"
  "\nWe can decrypt this message with any JWK using an input file or stdin:"
  "\n"
  "\n    $ jose dec -i /tmp/greeting.jws oct.jwk"
  "\n    hi"
  "\n"
  "\n    $ cat /tmp/greeting.jws | jose dec rsa.jwk"
  "\n    hi"
  "\n"
  "\nWhen we use a different key, however, decryption fails:"
  "\n"
  "\n    $ jose dec -i /tmp/greeting.jws ec.jwk"
  "\n    Decryption failed!"
  "\n\n"
};

static bool
header_has_pbes2(const json_t *jwe, const json_t *rcp)
{
    const char *alg = NULL;
    json_t *jh = NULL;
    int cmp = 0;

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        return false;

    json_unpack(jh, "{s:s}", "alg", &alg);
    cmp = strncmp(alg, "PBES2", strlen("PBES2"));
    json_decref(jh);
    return cmp == 0;
}

static bool
jwe_has_pbes2(const json_t *jwe)
{
    json_t *rcps = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (!json_is_array(rcps))
        return header_has_pbes2(jwe, jwe);

    for (size_t i = 0; i < json_array_size(rcps); i++) {
        if (header_has_pbes2(jwe, json_array_get(rcps, i)))
            return true;
    }

    return false;
}

static int
decrypt(const json_t *jwe, const json_t *cek, const char *to)
{
    uint8_t *out = NULL;
    size_t len = 0;

    out = jose_jwe_decrypt(jwe, cek, &len);
    if (!out) {
        fprintf(stderr, "Error during decryption!\n");
        return EXIT_FAILURE;
    }

    if (!jcmd_dump_file(to, out, len)) {
        fprintf(stderr, "Error dumping JWE!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
jcmd_dec(int argc, char *argv[])
{
    struct options opts = {};
    int ret = EXIT_FAILURE;
    json_t *jwe = NULL;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EXIT_FAILURE;

    jwe = jcmd_load(opts.in, NULL, jose_jwe_from_compact);
    if (!jwe)
        goto egress;

    for (size_t i = 0; i < json_array_size(opts.jwks); i++) {
        json_t *cek = NULL;

        cek = jose_jwe_unseal(jwe, json_array_get(opts.jwks, i));
        if (!cek)
            continue;

        ret = decrypt(jwe, cek, opts.out);
        json_decref(cek);
        goto egress;
    }

    if (jwe_has_pbes2(jwe) && !opts.nonint) {
        const char *pwd = NULL;

        pwd = getpass("Please enter password: ");
        if (pwd) {
            json_t *jwk = json_string(pwd);
            json_t *cek = NULL;

            cek = jose_jwe_unseal(jwe, jwk);
            json_decref(jwk);
            if (cek) {
                ret = decrypt(jwe, cek, opts.out);
                json_decref(cek);
                goto egress;
            }
        }
    }

    fprintf(stderr, "Decryption failed!\n");

egress:
    json_decref(opts.jwks);
    json_decref(jwe);
    return ret;
}
