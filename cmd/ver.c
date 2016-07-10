/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>

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

static const struct option opts[] = {
    { "all",    no_argument,       .val = 'a' },
    { "input",  required_argument, .val = 'i' },
    { "output", required_argument, .val = 'o' },
    {}
};

int
jcmd_ver(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *out = NULL;
    const char *in = NULL;
    json_t *jwks = NULL;
    json_t *jws = NULL;
    bool all = false;

    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "ai:o:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'i': in = optarg; break;
        case 'o': out = optarg; break;
        case 'a': all = true; break;
        default: goto usage;
        }
    }

    for (int i = optind; i < argc; i++) {
        json_t *tmp = jcmd_load(argv[i], argv[i], NULL);
        if (json_array_append_new(jwks, tmp) == -1) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK!\n\n");
        goto usage;
    }

    jws = jcmd_load(in, NULL, jose_jws_from_compact);
    if (!jws)
        goto egress;

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        bool valid = false;

        valid = jose_jws_verify(jws, json_array_get(jwks, i));
        if (valid && !all) {
            all = true;
            break;
        }

        if (!valid && all) {
            fprintf(stderr, "Signature validation failed!\n");
            goto egress;
        }
    }

    if (!all)
        fprintf(stderr, "No signatures validated!\n");
    else if (!dump(out, jws))
        fprintf(stderr, "Error dumping payload!\n");
    else
        ret = EXIT_SUCCESS;

egress:
    json_decref(jwks);
    json_decref(jws);
    return ret;

usage:
    fprintf(stderr,
    "Usage: %s [-a] [-i FILE] [-o FILE] JWK [...]"
    "\n"
    "\nVerifies a JWS using the supplied JWKs and outputs the payload."
    "\n"
    "\n    -a,      --all            Require verification of all JWKs"
    "\n    -i FILE, --input=FILE     JWS input file"
    "\n    -o FILE, --output=FILE    JWS output file"
    "\n"
    "\nHere are some examples. First, we create a signature with two keys:"
    "\n"
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
    "\n\n", argv[0]);
    goto egress;
}
