/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>

#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
#define PUB "\"x\": \"...\", \"y\": \"...\""
#define END " }"

struct options {
    const char *in;
    const char *out;
    jose_jwk_type_t types;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    static const struct {
        const char *kty;
        const char type;
    } table[] = {
        { "oct", JOSE_JWK_TYPE_OCT },
        { "RSA", JOSE_JWK_TYPE_RSA },
        { "EC", JOSE_JWK_TYPE_EC },
        { "sym", JOSE_JWK_TYPE_SYM },
        { "asym", JOSE_JWK_TYPE_ASYM },
        { "all", JOSE_JWK_TYPE_ALL },
        {}
    };

    struct options *opts = state->input;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;

    case 't':
        for (size_t i = 0; table[i].kty; i++) {
            if (strcmp(table[i].kty, arg) == 0)
                opts->types |= table[i].type;
        }

    case ARGP_KEY_FINI:
        if (opts->types == JOSE_JWK_TYPE_NONE)
            opts->types = JOSE_JWK_TYPE_ALL;
        return 0;

    default: return ARGP_ERR_UNKNOWN;
    }
}

static const struct argp argp = {
    .options = (const struct argp_option[]) {
        { "input", 'i', "filename", .doc = "JWK input file" },
        { "output", 'o', "filename", .doc = "JWK output file" },
        { "type", 't', "type", .doc = "JWK type to clean" },
        {}
    },
    .parser = parser,
    .args_doc = "[JWK]",
    .doc = "\nCleans private keys from a JWK.\n"
           "\vThis command simply takes a JWK as input and outputs a JWK:"
           "\n"
           "\n    $ jose pub -i ec.jwk"
           "\n    " START PUB END
           "\n"
           "\n    $ cat ec.jwk | jose pub"
           "\n    " START PUB END
           "\n\n"
};

int
jcmd_pub(int argc, char *argv[])
{
    struct options opts = {};
    json_t *jwk = NULL;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EXIT_FAILURE;

    jwk = jcmd_load(opts.in, NULL, NULL);
    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        return EXIT_FAILURE;
    }

    if (!jose_jwk_clean(jwk, opts.types)) {
        fprintf(stderr, "Error removing public keys!\n");
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
