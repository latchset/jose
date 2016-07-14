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

    out = jose_b64_decode(payload, &len);
    if (!out)
        goto egress;

    if (!jcmd_dump_data(filename, out, len))
        goto egress;

    ret = true;

egress:
    free(out);
    return ret;
}

static const struct option opts[] = {
    { "help",     no_argument,       .val = 'h' },

    { "all",      no_argument,       .val = 'a' },
    { "jwk",      required_argument, .val = 'k' },
    { "input",    required_argument, .val = 'i' },
    { "output",   required_argument, .val = 'o' },
    { "detached", required_argument, .val = 'd' },
    {}
};

int
jcmd_ver(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *det = NULL;
    const char *out = NULL;
    json_t *jwks = NULL;
    json_t *jws = NULL;
    bool all = false;

    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hak:i:o:d:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'a': all = true; break;
        case 'd': det = optarg; break;

        case 'i':
            json_decref(jws);
            jws = jcmd_load_json(optarg, NULL, jose_jws_from_compact);
            break;

        case 'k':
            if (!jcmd_jwks_extend(jwks, jcmd_load_json(optarg, NULL, NULL))) {
                fprintf(stderr, "Invalid JWK(Set): %s!\n", optarg);
                goto usage;
            }
            break;

        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK(Set)!\n\n");
        goto usage;
    }

    if (!jws) {
        fprintf(stderr, "Invalid JWS!\n");
        goto egress;
    }

    if (det) {
        uint8_t *py = NULL;
        size_t pyl = 0;
        int r = 0;

        py = jcmd_load_data(det, &pyl);
        if (!py) {
            fprintf(stderr, "Unable to load detatched payload: %s!\n", det);
            goto egress;
        }

        r = json_object_set_new(jws, "payload", jose_b64_encode_json(py, pyl));
        memset(py, 0, pyl);
        free(py);
        if (r < 0)
            goto egress;
    }

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
    else if (out && !dump(out, jws))
        fprintf(stderr, "Error dumping payload!\n");
    else
        ret = EXIT_SUCCESS;

egress:
    json_decref(jwks);
    json_decref(jws);
    return ret;

usage:
    fprintf(stderr,
"jose " VER_USE
"\n"
"\nVerifies a JWS using the supplied JWKs and outputs the payload."
"\n"
"\n    -i FILE, --input=FILE       JWS input (file)"
"\n    -i -,    --input=-          JWS input (stdin)"
"\n"
"\n    -d FILE, --detached=FILE    Detached payload input (file)"
"\n    -d -,    --detached=-       Detached payload input (stdin)"
"\n"
"\n    -k FILE, --jwk=FILE         JWK or JWKSet (file)"
"\n    -k -,    --jwk=-            JWK or JWKSet (stdin)"
"\n"
"\n    -a,      --all              Require verification of all JWKs"
"\n"
"\n    -o FILE, --output=FILE      JWS output (file)"
"\n    -o -,    --output=-         JWS output (stdout)"
"\n"
"\nHere are some examples. First, we create a signature with two keys:"
"\n"
"\n    $ echo hi | jose sig -i- -o /tmp/msg.jws -k rsa.jwk -k ec.jwk"
"\n"
"\nWe can verify this signature using an input file or stdin:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k ec.jwk -o-"
"\n    hi"
"\n"
"\n    $ cat /tmp/msg.jws | jose ver -i- -k rsa.jwk -o-"
"\n    hi"
"\n"
"\nWhen we use a different key, validation fails:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k oct.jwk -o-"
"\n    No signatures validated!"
"\n"
"\nNormally, we want validation to succeed if any key validates:"
"\n"
"\n    $ jose ver -i /tmp/msg.jws -k rsa.jwk -k oct.jwk -o-"
"\n    hi"
"\n"
"\nHowever, we can also require validation of all specified keys:"
"\n"
"\n    $ jose ver -a -i /tmp/msg.jws -k rsa.jwk -k oct.jwk -o-"
"\n    Signature validation failed!"
"\n\n");
    goto egress;
}
