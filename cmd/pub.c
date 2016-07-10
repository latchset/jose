/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>

#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
#define PUB "\"x\": \"...\", \"y\": \"...\""
#define END " }"

static const struct option opts[] = {
    { "type",      required_argument, .val = 't' },
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    {}
};

static const struct {
    const char *kty;
    const char type;
} type_table[] = {
    { "oct", JOSE_JWK_TYPE_OCT },
    { "RSA", JOSE_JWK_TYPE_RSA },
    { "EC", JOSE_JWK_TYPE_EC },
    { "sym", JOSE_JWK_TYPE_SYM },
    { "asym", JOSE_JWK_TYPE_ASYM },
    { "all", JOSE_JWK_TYPE_ALL },
    {}
};

int
jcmd_pub(int argc, char *argv[])
{
    jose_jwk_type_t types = JOSE_JWK_TYPE_NONE;
    int ret = EXIT_FAILURE;
    const char *out = NULL;
    const char *in = NULL;
    json_t *jwk = NULL;

    for (int c; (c = getopt_long(argc, argv, "i:o:t:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'i': in = optarg; break;
        case 'o': out = optarg; break;
        case 't':
            for (size_t i = 0; type_table[i].kty; i++) {
                if (strcmp(type_table[i].kty, optarg) == 0)
                    types |= type_table[i].type;
            }
            break;
        default: goto usage;
        }
    }

    if (types == JOSE_JWK_TYPE_NONE)
        types = JOSE_JWK_TYPE_ALL;

    jwk = jcmd_load(in, NULL, NULL);
    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        return EXIT_FAILURE;
    }

    if (!jose_jwk_clean(jwk, types)) {
        fprintf(stderr, "Error removing public keys!\n");
        goto egress;
    }

    if (!jcmd_dump(jwk, out, NULL)) {
        fprintf(stderr, "Error dumping JWK!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    json_decref(jwk);
    return ret;

usage:
    fprintf(stderr,
    "Usage: %s [-i FILE] [-o FILE] [-t oct|EC|RSA|sym|asym|all ...]"
    "\n"
    "\nCleans private keys from a JWK."
    "\n"
    "\n    -i FILE, --input=FILE     JWK input file"
    "\n    -o FILE, --output=FILE    JWK output file"
    "\n    -t FILE, --type=TYPE      JWK type"
    "\n"
    "\nThis command simply takes a JWK as input and outputs a JWK:"
    "\n"
    "\n    $ jose pub -i ec.jwk"
    "\n    " START PUB END
    "\n"
    "\n    $ cat ec.jwk | jose pub"
    "\n    " START PUB END
    "\n\n", argv[0]);
    goto egress;
}
