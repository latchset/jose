/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>

static bool
load(const char *in, json_t *tmpl)
{
    uint8_t *buf = NULL;
    size_t len = 0;

    buf = in ? jcmd_load_file(in, &len) : jcmd_load_stdin(&len);
    if (!buf) {
        fprintf(stderr, "Error reading payload!\n");
        return false;
    }

    if (json_object_set_new(tmpl, "payload",
                            jose_b64_encode_json(buf, len)) < 0) {
        fprintf(stderr, "Error encoding payload!\n");
        free(buf);
        return false;
    }

    free(buf);
    return true;
}

static const struct option opts[] = {
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "compact",   no_argument,       .val = 'c' },
    { "template",  required_argument, .val = 't' },
    { "signature", required_argument, .val = 's' },
    {}
};

int
jcmd_sig(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *out = NULL;
    const char *in = NULL;
    bool compact = NULL;
    json_t *tmpl = NULL;
    json_t *sigs = NULL;
    json_t *jwks = NULL;
    json_t *tmp = NULL;

    tmpl = json_object();
    sigs = json_array();
    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "i:o:ct:s:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'i': in = optarg; break;
        case 'o': out = optarg; break;
        case 'c': compact = true; break;

        case 't':
            json_decref(tmpl);
            tmpl = jcmd_load(optarg, optarg, jose_jws_from_compact);
            if (!tmpl) {
                fprintf(stderr, "Invalid JWS template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 's':
            tmp = jcmd_load(optarg, optarg, NULL);
            if (json_array_append_new(sigs, tmp) == -1) {
                fprintf(stderr, "Invalid JWS signature template: %s!\n",
                        optarg);
                goto usage;
            }

            break;

        default:
            goto usage;
        }
    }

    for (int i = optind; i < argc; i++) {
        tmp = jcmd_load(argv[i], argv[i], NULL);
        if (json_array_append_new(jwks, tmp) == -1) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            goto usage;
        }
    }

    if (json_array_size(jwks) == 0) {
        fprintf(stderr, "MUST specify a JWK!\n\n");
        goto usage;
    }

    if (!json_object_get(tmpl, "payload") && !load(in, tmpl))
        goto egress;

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        if (!jose_jws_sign(tmpl, json_array_get(jwks, i),
                           json_incref(json_array_get(sigs, i)))) {
            fprintf(stderr, "Error creating signature!\n");
            goto egress;
        }
    }

    if (!jcmd_dump(tmpl, out, compact ? jose_jws_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    json_decref(tmpl);
    json_decref(sigs);
    json_decref(jwks);
    return ret;

usage:
    fprintf(stderr,
    "Usage: %s [-c] [-i FILE] [-o FILE] [-t TMPL] [-s SIG ...] JWK [...]"
    "\n"
    "\nSigns a payload using one or more JWKs and outputs a JWS."
    "\n"
    "\n    -c,      --compact          Use JWS compact format"
    "\n    -i FILE, --input=FILE       Payload input file"
    "\n    -o FILE, --output=FILE      JWS output file"
    "\n    -t TMPL, --template=TMPL    JWS template (JSON or file)"
    "\n    -s SIG,  --signature=SIG    JWS signature template (JSON or file)"
    "\n"
    "\nWhen creating multiple signatures, JWS general format is used:"
    "\n"
    "\n    $ echo hi | jose sig ec.jwk rsa.jwk"
    "\n    { \"payload\": \"aGkK\", \"signatures\": ["
    "\n      { \"protected\": \"...\", \"signature\": \"...\" },"
    "\n      { \"protected\": \"...\", \"signature\": \"...\" } ] }"
    "\n"
    "\nWith a single signature, JWS flattened format is used:"
    "\n"
    "\n    $ echo hi | jose sig ec.jwk"
    "\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
    "\n"
    "\nAlternatively, JWS compact format may be used:"
    "\n"
    "\n    $ echo hi | jose sig -c ec.jwk"
    "\n    eyJhbGciOiJFUzI1NiJ9.aGkK.VauBzVLMesMtTtGfwVOHh9WN1dn6iuEkmebFpJJu..."
    "\n"
    "\nIf the payload is specified in the template, stdin is not used:"
    "\n"
    "\n    $ jose sig -t '{ \"payload\": \"aGkK\" }' rsa.jwk"
    "\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
    "\n"
    "\nThe same is true when using an input file:"
    "\n"
    "\n    $ jose sig -i message.txt rsa.jwk"
    "\n    { \"payload\": \"aGkK\", \"protected\": \"...\", \"signature\": \"...\" }"
    "\n\n", argv[0]);
    goto egress;
}
