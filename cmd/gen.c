/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>

#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\""
#define KEYS ", \"x\": \"...\", \"y\": \"...\", \"d\": \"...\""
#define END " }"

static const struct option opts[] = {
    { "output",    required_argument, .val = 'o' },
    { "template",  required_argument, .val = 't' },
    {}
};

int
jcmd_gen(int argc, char *argv[])
{
    const char *tmpl = NULL;
    const char *out = NULL;
    int ret = EXIT_FAILURE;
    json_t *jwk = NULL;

    for (int c; (c = getopt_long(argc, argv, "o:t:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'o': out = optarg; break;
        case 't': tmpl = optarg; break;
        default: goto usage;
        }
    }

    jwk = jcmd_load(tmpl, tmpl, NULL);
    if (!jwk || !jose_jwk_generate(jwk)) {
        fprintf(stderr, "Invalid template!\n");
        goto usage;
    }

    if (jcmd_dump(jwk, out, NULL))
        ret = EXIT_SUCCESS;
    else
        fprintf(stderr, "Error dumping JWK!\n");

egress:
    json_decref(jwk);
    return ret;

usage:
    fprintf(stderr,
    "Usage: %s [-o FILE] [-t TMPL]"
    "\n"
    "\nCreates a new, random JWK from a JWK template."
    "\n"
    "\n    -o FILE, --output=FILE      JWK output file"
    "\n    -t TMPL, --template=TMPL    JWK template (JSON or file)"
    "\n"
    "\nThe simplest way to create a new key is to specify the algorithm that "
    "\nwill be used with the key. For example:"
    "\n"
    "\n    $ echo '{\"alg\":\"A128GCM\"}' | jose gen"
    "\n    { \"kty\": \"oct\", \"k\": \"...\", \"alg\": \"A128GCM\","
    "\n      \"use\": \"enc\", \"key_ops\": [\"encrypt\", \"decrypt\"] }"
    "\n"
    "\n    $ jose gen -t '{\"alg\":\"RSA1_5\"}'"
    "\n    { \"kty\": \"RSA\", \"alg\": \"RSA1_5\", \"use\": \"enc\","
    "\n      \"key_ops\": [\"wrapKey\", \"unwrapKey\"], ... }"
    "\n"
    "\nNote that when specifying an algorithm, default parameters such as "
    "\n\"use\" and \"key_ops\" will be created if not specified."
    "\n"
    "\nAlternatively, key parameters can be specified directly:"
    "\n"
    "\n    $ jose gen -t '" START END "'"
    "\n    " START KEYS END "\n"
    "\n    $ jose gen -t '{\"kty\": \"oct\", \"bytes\": 32}'"
    "\n    { \"kty\": \"oct\", \"k\": \"...\" }\n"
    "\n    $ jose gen -t '{\"kty\": \"RSA\", \"bits\": 4096}'"
    "\n    { \"kty\": \"RSA\", \"n\": \"...\", \"e\": \"...\", ... }"
    "\n\n", argv[0]);
    goto egress;
}
