/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>
#include <unistd.h>
#include <string.h>

static bool
header_has_pbes2(const json_t *jwe, const json_t *rcp)
{
    const char *alg = NULL;
    json_t *jh = NULL;
    int cmp = 0;

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        return false;

    json_unpack(jh, "{s:s}", "alg", &alg);
    cmp = strncmp(alg, "PBES2", strlen("PBES2"));
    json_decref(jh);
    return cmp == 0;
}

static bool
jwe_has_pbes2(const json_t *jwe)
{
    json_t *rcps = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (!json_is_array(rcps))
        return header_has_pbes2(jwe, jwe);

    for (size_t i = 0; i < json_array_size(rcps); i++) {
        if (header_has_pbes2(jwe, json_array_get(rcps, i)))
            return true;
    }

    return false;
}

static int
decrypt(const json_t *jwe, const json_t *cek, const char *to)
{
    uint8_t *out = NULL;
    size_t len = 0;

    out = jose_jwe_decrypt(jwe, cek, &len);
    if (!out) {
        fprintf(stderr, "Error during decryption!\n");
        return EXIT_FAILURE;
    }

    if (!jcmd_dump_data(to, out, len)) {
        fprintf(stderr, "Error dumping JWE!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },

    { "jwk",       required_argument, .val = 'k' },
    { "input",     required_argument, .val = 'i' },
    { "output",    required_argument, .val = 'o' },
    { "no-prompt", no_argument,       .val = 'n' },
    {}
};

int
jcmd_dec(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *out = "-";
    json_t *jwks = NULL;
    bool nonint = false;
    json_t *jwe = NULL;

    jwks = json_array();

    for (int c; (c = getopt_long(argc, argv, "hk:i:o:n", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'n': nonint = true; break;

        case 'i':
            json_decref(jwe);
            jwe = jcmd_load_json(optarg, NULL, jose_jwe_from_compact);
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

    if (!jwe) {
        fprintf(stderr, "Invalid JWE!\n");
        goto usage;
    }

    if (json_array_size(jwks) == 0 && nonint) {
        fprintf(stderr, "MUST specify a JWK in non-interactive mode!\n\n");
        goto usage;
    }

    for (size_t i = 0; i < json_array_size(jwks); i++) {
        json_t *cek = NULL;

        cek = jose_jwe_unwrap(jwe, json_array_get(jwks, i));
        if (!cek)
            continue;

        ret = decrypt(jwe, cek, out);
        json_decref(cek);
        goto egress;
    }

    if (jwe_has_pbes2(jwe) && !nonint) {
        const char *pwd = NULL;

        pwd = getpass("Please enter password: ");
        if (pwd) {
            json_t *jwk = json_string(pwd);
            json_t *cek = NULL;

            cek = jose_jwe_unwrap(jwe, jwk);
            json_decref(jwk);
            if (cek) {
                ret = decrypt(jwe, cek, out);
                json_decref(cek);
                goto egress;
            }
        }
    }

    fprintf(stderr, "Decryption failed!\n");

egress:
    json_decref(jwks);
    json_decref(jwe);
    return ret;

usage:
    fprintf(stderr,
"jose " DEC_USE
"\n"
"\nDecrypts a JWE using the supplied JWK(Set) and outputs the plaintext."
"\n"
"\n    -n,      --no-prompt      Do not prompt for password"
"\n"
"\n    -k FILE, --jwk=FILE       JWK or JWKSet (file)"
"\n    -k -,    --jwk=-          JWK or JWKSet (stdin)"
"\n"
"\n    -i FILE, --input=FILE     JWE input (file)"
"\n    -i -,    --input=-        JWE input (stdin)"
"\n"
"\n    -o FILE, --output=FILE    Plaintext payload (file)"
"\n    -o -,    --output=-       Plaintext payload (stdout; default)"
"\n"
"\nHere are some examples. First, we encrypt a message with three keys:"
"\n"
"\n    $ echo hi | jose enc -i- -o /tmp/msg.jwe -p -k rsa.jwk -k oct.jwk"
"\n    Please enter a password:"
"\n    Please re-enter the previous password:"
"\n"
"\nWe can decrypt this message with any JWK using an input file or stdin:"
"\n"
"\n    $ jose dec -i /tmp/msg.jwe -k oct.jwk"
"\n    hi"
"\n"
"\n    $ cat /tmp/msg.jwe | jose dec -i- -k rsa.jwk"
"\n    hi"
"\n"
"\nWe can also decrypt this message using the password:"
"\n"
"\n    $ jose dec -i /tmp/msg.jwe"
"\n    Please enter password:"
"\n    hi"
"\n"
"\nWhen we use a different key and suppress prompting, decryption fails:"
"\n"
"\n    $ jose dec -n -i /tmp/msg.jwe -k ec.jwk"
"\n    Decryption failed!"
"\n\n");
    goto egress;
}
