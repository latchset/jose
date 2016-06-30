/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"
#include <string.h>

#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\""
#define KEYS ", \"x\": \"...\", \"y\": \"...\", \"d\": \"...\""
#define END " }"

struct options {
    const char *out;
    const char *tmpl;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'o': opts->out = arg; return 0;
    case 't': opts->tmpl = arg; return 0;
    default: return ARGP_ERR_UNKNOWN;
    }
}

static const struct argp argp = {
    .options = (const struct argp_option[]) {
        { "output",   'o', "FILENAME", .doc = "JWK output file" },
        { "template", 't', "TEMPLATE", .doc = "JWK template (JSON or file)" },
        {}
    },
    .parser = parser,
    .doc = "\nCreates a new, random JWK from a JWK template.\n"
           "\vThe simplest way to create a new key is to specify the algorithm"
           " that will be used with the key. For example:"
           "\n"
           "\n    $ echo '{\"alg\":\"A128GCM\"}' | jose gen"
           "\n    { \"kty\": \"oct\", \"k\": \"...\", \"alg\": \"A128GCM\","
           "\n      \"use\": \"enc\", \"key_ops\": [\"encrypt\", \"decrypt\"] }"
           "\n"
           "\n    $ jose gen -t '{\"alg\":\"RSA1_5\"}'"
           "\n    { \"kty\": \"RSA\", \"alg\": \"RSA1_5\", \"use\": \"enc\","
           "\n      \"key_ops\": [\"wrapKey\", \"unwrapKey\"], ... }"
           "\n"
           "\nNote that when specifying an algorithm, default parameters such"
           " as \"use\" and \"key_ops\" will be created if not specified.\n"
           "\nAlternatively, key parameters can be specified directly:\n"
           "\n    $ jose gen -t '" START END "'"
           "\n    " START KEYS END "\n"
           "\n    $ jose gen -t '{\"kty\": \"oct\", \"bytes\": 32}'"
           "\n    { \"kty\": \"oct\", \"k\": \"...\" }\n"
           "\n    $ jose gen -t '{\"kty\": \"RSA\", \"bits\": 4096}'"
           "\n    { \"kty\": \"RSA\", \"n\": \"...\", \"e\": \"...\", ... }\n\n"
};

int
jcmd_gen(int argc, char *argv[])
{
    struct options opts = {};
    json_t *jwk = NULL;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EXIT_FAILURE;

    jwk = jcmd_load(opts.tmpl, opts.tmpl, NULL);
    if (!jwk || !jose_jwk_generate(jwk)) {
        fprintf(stderr, "Invalid template!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (!jcmd_dump(jwk, opts.out, NULL)) {
        fprintf(stderr, "Error dumping JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    json_decref(jwk);
    return EXIT_SUCCESS;
}
