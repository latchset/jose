/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <string.h>
#include <unistd.h>

static json_t *
mkcek(json_t *tmpl)
{
    const char *penc = NULL;
    const char *senc = NULL;
    json_t *cek = NULL;

    if (json_unpack(tmpl, "{s?{s?s},s?{s?s}}",
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

static const char *
prompt(void)
{
    const char *c = NULL;
    char *p = NULL;

    while (!p || !c || strcmp(p, c) != 0) {
        free(p);

        p = strdup(getpass("Please enter a password: "));
        if (!p)
            continue;

        if (strlen(p) < 8) {
            fprintf(stderr, "Password too short!\n");
            continue;
        }

        c = getpass("Please re-enter the previous password: ");
    }

    free(p);
    return c;
}

static const struct option opts[] = {
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "compact",   no_argument,       .val = 'c' },
    { "template",  required_argument, .val = 't' },
    { "password",  no_argument,       .val = 'p' },
    { "recipient", required_argument, .val = 'r' },
    {}
};

int
jcmd_enc(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *out = NULL;
    const char *in = NULL;
    bool compact = false;
    json_t *tmpl = NULL;
    json_t *rcps = NULL;
    json_t *jwks = NULL;
    uint8_t *buf = NULL;
    json_t *tmp = NULL;
    json_t *cek = NULL;
    size_t len = 0;

    tmpl = json_object();
    rcps = json_array();
    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "i:o:ct:pr:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'i': in = optarg; break;
        case 'o': out = optarg; break;
        case 'c': compact = true; break;

        case 't':
            json_decref(tmpl);
            tmpl = jcmd_load(optarg, optarg, jose_jwe_from_compact);
            if (!tmpl) {
                fprintf(stderr, "Invalid JWE template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 'r':
            tmp = jcmd_load(optarg, optarg, NULL);
            if (json_array_append_new(rcps, tmp) == -1) {
                fprintf(stderr, "Invalid JWE recipient template: %s!\n", optarg);
                goto usage;
            }

            break;

        case 'p':
            if (json_array_append_new(jwks, json_string(prompt())) == -1) {
                fprintf(stderr, "Error adding password!\n");
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
        fprintf(stderr, "MUST specify a JWK or password!\n\n");
        goto usage;
    }

    buf = in ? jcmd_load_file(in, &len) : jcmd_load_stdin(&len);
    if (!buf) {
        fprintf(stderr, "Error loading the plaintext!\n");
        goto egress;
    }

    cek = mkcek(tmpl);
    if (!cek) {
        fprintf(stderr, "Error building the CEK!\n");
        goto egress;
    }

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        if (!jose_jwe_seal(tmpl, cek, json_array_get(jwks, i),
                           json_incref(json_array_get(rcps, i)))) {
            fprintf(stderr, "Error creating seal!\n");
            goto egress;
        }
    }

    if (compact) {
        json_t *jh = NULL;

        if (json_object_get(tmpl, "recipients")) {
            fprintf(stderr, "Requested compact format with >1 recipient!\n");
            goto egress;
        }

        jh = jose_jwe_merge_header(tmpl, tmpl);
        if (!jh)
            goto egress;

        if (json_object_set_new(tmpl, "protected", jh) == -1)
            goto egress;

        if (json_object_get(tmpl, "unprotected") &&
            json_object_del(tmpl, "unprotected") == -1)
            goto egress;

        if (json_object_get(tmpl, "header") &&
            json_object_del(tmpl, "header") == -1)
            goto egress;
    }

    if (!jose_jwe_encrypt(tmpl, cek, buf, len)) {
        fprintf(stderr, "Error encrypting input!\n");
        goto egress;
    }

    if (!jcmd_dump(tmpl, out, compact ? jose_jwe_to_compact : NULL)) {
        fprintf(stderr, "Error dumping JWS!\n");
        goto egress;
    }

    ret = EXIT_SUCCESS;

egress:
    if (buf)
        memset(buf, 0, len);
    json_decref(tmpl);
    json_decref(rcps);
    json_decref(jwks);
    json_decref(cek);
    free(buf);
    return ret;

usage:
    fprintf(stderr,
    "Usage: %s [-c] [-p ...] [-i FILE] [-o FILE] [-t TMPL] [-r RCP ...] JWK [...]"
    "\n"
    "\nEncrypts plaintext using one or more JWKs and outputs a JWE."
    "\n"
    "\n    -c,      --compact          Output JWE in compact format"
    "\n    -p,      --password         Use a password for encryption (repeatable)"
    "\n    -i FILE, --input=FILE       Plaintext input file"
    "\n    -o FILE, --output=FILE      Ciphertext output file"
    "\n    -t TMPL, --template=TMPL    JWE template (JSON or file)"
    "\n    -r RCP,  --template=RCP     JWE recipient template (JSON or file)"
    "\n"
    "\nWhen encrypting to multiple recipients, JWE general format is used:"
    "\n"
    "\n    $ echo hi | jose enc rsa.jwk oct.jwk"
    "\n    { \"ciphertext\": \"...\", \"recipients\": [{...}, {...}], ...}"
    "\n"
    "\nWith a single recipient, JWE flattened format is used:"
    "\n"
    "\n    $ echo hi | jose enc rsa.jwk"
    "\n    { \"ciphertext\": \"...\", \"encrypted_key\": \"...\", ... }"
    "\n"
    "\nAlternatively, JWE compact format may be used:"
    "\n"
    "\n    $ echo hi | jose enc -c rsa.jwk"
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
    "\n\n", argv[0]);
    goto egress;
}
