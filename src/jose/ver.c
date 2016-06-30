/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"
#include <string.h>

struct options {
    const char *out;
    const char *in;
    json_t *jwks;
    bool all;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;
    case 'a': opts->all = true; return 0;

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
        { "input", 'i', "filename", .doc = "JWS input file" },
        { "output", 'o', "filename", .doc = "JWS output file" },
        { "all", 'a', .doc = "Require verification of all JWKs" },
        {}
    },
    .parser = parser,
    .args_doc = "JWK [JWK ...]",
    .doc =
  "\nVerifies a JWS using the supplied JWKs and outputs the payload.\n"
  "\vHere are some examples. First, we create a signature with two keys:\n"
  "\n    $ echo hi | jose sig -o /tmp/greeting.jws rsa.jwk ec.jwk"
  "\n"
  "\nWe can verify this signature using an input file or stdin:"
  "\n"
  "\n    $ jose ver -i /tmp/greeting.jws ec.jwk"
  "\n    hi"
  "\n"
  "\n    $ cat /tmp/greeting.jws | jose ver rsa.jwk"
  "\n    hi"
  "\n"
  "\nWhen we use a different key, validation fails:"
  "\n"
  "\n    $ jose ver -i /tmp/greeting.jws oct.jwk"
  "\n    No signatures validated!"
  "\n"
  "\nNormally, we want validation to succeed if any key validates:"
  "\n"
  "\n    $ jose ver -i /tmp/greeting.jws rsa.jwk oct.jwk"
  "\n    hi"
  "\n"
  "\nHowever, we can also require validation of all specified keys:"
  "\n"
  "\n    $ jose ver -a -i /tmp/greeting.jws rsa.jwk oct.jwk"
  "\n    Signature validation failed!"
  "\n\n"
};

static bool
dump(const char *filename, const json_t *jws)
{
    const char *payload = NULL;
    uint8_t *out = NULL;
    bool ret = false;
    size_t len = 0;

    if (json_unpack((json_t *) jws, "{s:s}", "payload", &payload) < 0)
        return false;

    out = jose_b64_decode_buf(payload, &len);
    if (!out)
        goto egress;

    if (!jcmd_dump_file(filename, out, len))
        goto egress;

    ret = true;

egress:
    free(out);
    return ret;
}

int
jcmd_ver(int argc, char *argv[])
{
    struct options opts = {};
    int ret = EXIT_FAILURE;
    json_t *jws = NULL;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EXIT_FAILURE;

    jws = jcmd_load(opts.in, NULL, jose_jws_from_compact);
    if (!jws)
        goto egress;

    for (size_t i = 0; i < json_array_size(opts.jwks); i++) {
        bool valid = false;

        valid = jose_jws_verify(jws, json_array_get(opts.jwks, i));
        if (valid && !opts.all) {
            opts.all = true;
            break;
        }

        if (!valid && opts.all) {
            fprintf(stderr, "Signature validation failed!\n");
            goto egress;
        }
    }

    if (!opts.all)
        fprintf(stderr, "No signatures validated!\n");
    else if (!dump(opts.out, jws))
        fprintf(stderr, "Error dumping payload!\n");
    else
        ret = EXIT_SUCCESS;

egress:
    json_decref(opts.jwks);
    json_decref(jws);
    return ret;
}
