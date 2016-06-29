/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

int
jose_decrypt(int argc, char *argv[])
{
    json_t *jwe = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    jwe = load_compact(stdin, jose_jwe_from_compact);
    if (!jwe)
        return EXIT_FAILURE;

    for (int i = 2; i < argc; i++) {
        json_t *cek = NULL;
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            goto error;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            goto error;
        }

        cek = jose_jwe_unseal(jwe, jwk);
        if (cek) {
            uint8_t *out = NULL;
            size_t len = 0;

            out = jose_jwe_decrypt(jwe, cek, &len);
            if (!out) {
                fprintf(stderr, "Error during decryption!\n");
                json_decref(cek);
                json_decref(jwk);
                goto error;
            }

            fwrite(out, 1, len, stdout);
            json_decref(cek);
            json_decref(jwe);
            json_decref(jwk);
            free(out);
            return EXIT_SUCCESS;
        }

        json_decref(jwk);
    }

    fprintf(stderr, "Decryption failed!\n");

error:
    json_decref(jwe);
    return EXIT_FAILURE;
}
