/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>
#include <unistd.h>

struct options {
    const char *in;
    const char *out;
    bool compact;
    json_t *tmpl;
    json_t *rcps;
    json_t *jwks;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
    struct options *opts = state->input;
    char *password = NULL;
    char *confirm = NULL;

    switch (key) {
    case 'i': opts->in = arg; return 0;
    case 'o': opts->out = arg; return 0;
    case 'c': opts->compact = true; return 0;

    case 't':
        json_decref(opts->tmpl);
        opts->tmpl = jcmd_load(arg, arg, jose_jwe_from_compact);
        if (!opts->tmpl) {
            fprintf(stderr, "Invalid JWE template: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

        return 0;

    case 'r':
        if (!opts->rcps)
            opts->rcps = json_array();

        if (json_array_append_new(opts->rcps,
                                  jcmd_load(arg, arg, NULL)) == -1) {
            fprintf(stderr, "Invalid JWE recipient template: %s!\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

        return 0;

    case 'p':
        if (!opts->jwks)
            opts->jwks = json_array();

        do {
            free(password);
            password = strdup(getpass("Please enter a password: "));
            if (!password)
                continue;

            if (strlen(password) < 8) {
                fprintf(stderr, "Password too short!\n");
                continue;
            }

            confirm = getpass("Please re-enter the previous password: ");
        } while (!password || !confirm || strcmp(password, confirm) != 0);

        free(password);
        if (json_array_append_new(opts->jwks, json_string(confirm)) == -1) {
            fprintf(stderr, "Error adding password!\n");
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
            fprintf(stderr, "MUST specify a JWK or password!\n\n");
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
        { "input", 'i', "filename", .doc = "Plaintext file" },
        { "output", 'o', "filename", .doc = "JWE output file" },
        { "compact", 'c', .doc = "Output JWE in compact form" },
        { "template", 't', "jwe", .doc = "JWE template (JSON or file)" },
        { "password", 'p', .doc = "Prompt for a password (repeatable)" },
        { "recipient", 'r', "rcp",
            .doc = "JWE recipient template (JSON or file)" },
        {}
    },
    .parser = parser,
    .args_doc = "JWK [JWK ...]",
    .doc =
  "\nEncrypts plaintext using one or more JWKs and outputs a JWE.\n"
  "\vWhen encrypting to multiple recipients, JWE general format is used:"
  "\n"
  "\n    $ echo hi | jose enc rsa.jwk oct.jwk"
  "\n    { \"ciphertext\": \"...\", \"recipients\": [{...}, {...}], ...}"
  "\n"
  "\nWith a single recipient, JWE flattened format is used:"
  "\n"
  "\n    $ echo hi | jose enc rsa.jwk"
  "\n    { \"ciphertext\": \"...\", \"encrypted_key\": \"...\", ... }"
  "\n"
  "\nAlternatively, if you ensure that no shared or unprotected headers "
  "would be generated, JWE compact format may be used:"
  "\n"
  "\n    $ echo hi | jose enc -c -t '{\"protected\":{\"alg\":\"RSA1_5\"}}' rsa.jwk"
  "\n    eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZBRtX0Z0vaCMMg..."
  "\n"
  "\nBy tweaking the JWE template, you can choose alternate crypto parameters:"
  "\n"
  "\n    $ echo hi | jose enc -t '{\"unprotected\":{\"enc\":\"A128GCM\"}}' rsa.jwk"
  "\n    { \"ciphertext\": \"...\", \"unprotected\": { \"enc\": \"A128GCM\" }, ... }"
  "\n"
  "\nTransparent plaintext compression is also supported:"
  "\n"
  "\n    $ echo hi | jose enc -t '{\"protected\":{\"zip\":\"DEF\"}}' rsa.jwk"
  "\n    { \"ciphertext\": \"...\", ... }"
  "\n"
  "\nYou can encrypt to one or more passwords by using the '-p' option. This "
  "can even be mixed with JWKs:"
  "\n"
  "\n    $ echo hi | jose enc -p"
  "\n    Please enter a password:"
  "\n    Please re-enter the previous password:"
  "\n    { \"ciphertext\": \"...\", ... }"
  "\n"
  "\n    $ echo hi | jose enc -p rsa.jwk -p oct.jwk"
  "\n    Please enter a password:"
  "\n    Please re-enter the previous password:"
  "\n    Please enter a password:"
  "\n    Please re-enter the previous password:"
  "\n    { \"ciphertext\": \"...\", ... }"
  "\n\n"
};

static json_t *
mkcek(const struct options *opts)
{
    const char *penc = NULL;
    const char *senc = NULL;
    json_t *cek = NULL;

    if (json_unpack(opts->tmpl, "{s?{s?s},s?{s?s}}",
                    "protected", "enc", &penc,
                    "unprotected", "enc", &senc) == -1)
        return NULL;

    cek = json_pack("{s:s}", "alg",
                    penc ? penc : senc ? senc : "A128CBC-HS256");
    if (!cek)
        return NULL;

    if (!jose_jwk_generate(cek)) {
        json_decref(cek);
        return NULL;
    }

    return cek;
}

int
jcmd_enc(int argc, char *argv[])
{
    struct options opts = {};
    int ret = EXIT_FAILURE;
    uint8_t *buf = NULL;
    json_t *cek = NULL;
    size_t len = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        goto egress;

    buf = opts.in ? jcmd_load_file(opts.in, &len) : jcmd_load_stdin(&len);
    if (!buf) {
        fprintf(stderr, "Error loading the plaintext!\n");
        goto egress;
    }

    cek = mkcek(&opts);
    if (!cek) {
        fprintf(stderr, "Error building the CEK!\n");
        goto egress;
    }

    if (!jose_jwe_encrypt(opts.tmpl, cek, buf, len)) {
        fprintf(stderr, "Error encrypting input!\n");
        goto egress;
    }

    for (size_t i = 0; i < json_array_size(opts.jwks); i++) {
        if (!jose_jwe_seal(opts.tmpl, cek, json_array_get(opts.jwks, i),
                           json_incref(json_array_get(opts.rcps, i)))) {
            fprintf(stderr, "Error creating seal!\n");
            goto egress;
        }
    }

    if (!jcmd_dump(opts.tmpl, opts.out,
                   opts.compact ? jose_jwe_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    json_decref(opts.tmpl);
    json_decref(opts.rcps);
    json_decref(opts.jwks);
    json_decref(cek);
    free(buf);
    return ret;
}
