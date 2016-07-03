/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>

struct options {
    const char *out;
    const char *in;
    json_t *jwks;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;

    case ARGP_KEY_ARG:
        if (!opts->jwks)
            opts->jwks = json_array();

        if (json_array_append_new(opts->jwks,
                                  jcmd_load(arg, arg, NULL)) == -1) {
            fprintf(stderr, "Invalid JWK: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

    case ARGP_KEY_FINI:
        if (json_array_size(opts->jwks) == 0) {
            fprintf(stderr, "MUST specify a JWK!\n\n");
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
        uint8_t *out = NULL;
        json_t *cek = NULL;
        size_t len = 0;

        cek = jose_jwe_unseal(jwe, json_array_get(opts.jwks, i));
        if (!cek)
            continue;

        out = jose_jwe_decrypt(jwe, cek, &len);
        json_decref(cek);
        if (!out) {
            fprintf(stderr, "Error during decryption!\n");
            goto egress;
        }

        if (!jcmd_dump_file(opts.out, out, len)) {
            fprintf(stderr, "Error dumping JWE!\n");
            goto egress;
        }

        ret = EXIT_SUCCESS;
        goto egress;
    }

    fprintf(stderr, "Decryption failed!\n");

egress:
    json_decref(opts.jwks);
    json_decref(jwe);
    return ret;
}
