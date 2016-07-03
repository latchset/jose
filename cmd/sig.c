/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>

struct options {
    const char *in;
    const char *out;
    bool compact;
    json_t *tmpl;
    json_t *sigs;
    json_t *jwks;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;
    case 'c': opts->compact = true; return 0;

    case 't':
        json_decref(opts->tmpl);
        opts->tmpl = jcmd_load(arg, arg, jose_jws_from_compact);
        if (!opts->tmpl) {
            fprintf(stderr, "Invalid JWS template: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

        return 0;

    case 's':
        if (!opts->sigs)
            opts->sigs = json_array();

        if (json_array_append_new(opts->sigs,
                                  jcmd_load(arg, arg, NULL)) == -1) {
            fprintf(stderr, "Invalid JWS signature template: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

        return 0;

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

        if (!opts->tmpl)
            opts->tmpl = json_object();

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

static const struct argp argp = {
    .options = (const struct argp_option[]) {
        { "input", 'i', "filename", .doc = "Signature payload file" },
        { "output", 'o', "filename", .doc = "JWS output file" },
        { "compact", 'c', .doc = "Output JWS in compact form" },
        { "template", 't', "jws", .doc = "JWS template (JSON or file)" },
        { "signature", 's', "sig", .doc = "JWS signature template (JSON or file)" },
        {}
    },
    .parser = parser,
    .args_doc = "JWK [JWK ...]",
    .doc =
  "\nSigns a payload using one or more JWKs and outputs a JWS.\n"
  "\vWhen creating multiple signatures, JWS general format is used:"
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
  "\n\n"
};

static bool
load(const struct options *opts)
{
    uint8_t *buf = NULL;
    size_t len = 0;

    buf = opts->in ? jcmd_load_file(opts->in, &len) : jcmd_load_stdin(&len);
    if (!buf) {
        fprintf(stderr, "Error reading payload!\n");
        return false;
    }

    if (json_object_set_new(opts->tmpl, "payload",
                            jose_b64_encode_json(buf, len)) < 0) {
        fprintf(stderr, "Error encoding payload!\n");
        free(buf);
        return false;
    }

    free(buf);
    return true;
}

int
jcmd_sig(int argc, char *argv[])
{
    struct options opts = {};
    int ret = EXIT_FAILURE;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        goto egress;

    if (!json_object_get(opts.tmpl, "payload") && !load(&opts))
        goto egress;

    for (size_t i = 0; i < json_array_size(opts.jwks); i++) {
        if (!jose_jws_sign(opts.tmpl, json_array_get(opts.jwks, i),
                           json_incref(json_array_get(opts.sigs, i)))) {
            fprintf(stderr, "Error creating signature!\n");
            goto egress;
        }
    }

    if (!jcmd_dump(opts.tmpl, opts.out,
                   opts.compact ? jose_jws_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    json_decref(opts.tmpl);
    json_decref(opts.sigs);
    json_decref(opts.jwks);
    return ret;
}
