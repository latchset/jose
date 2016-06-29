/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

int
jose_encrypt(int argc, char *argv[])
{
    const char *enc = NULL;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *b = NULL;
    size_t l = 0;

    if (argc < 4)
        return EXIT_FAILURE;

    jwe = json_loads(argv[2], 0, NULL);
    if (!jwe) {
        fprintf(stderr, "Invalid template!\n");
        return EXIT_FAILURE;
    }

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(b, l + 512);
        if (!tmp) {
            fprintf(stderr, "Out of memory!\n");
            json_decref(jwe);
            return EXIT_FAILURE;
        }

        b = tmp;
        r = fread(&b[l], 1, 512, stdin);
        l += r;
    }

    if (json_unpack(jwe, "{s:s}", "enc", &enc) == -1) {
        fprintf(stderr, "Error finding encryption algorithm!\n");
        json_decref(jwe);
        free(b);
        return EXIT_FAILURE;
    }

    if (!enc)
        enc = "A128CBC-HS256";

    cek = json_pack("{s:s}", "alg", enc);
    if (!cek) {
        fprintf(stderr, "Error creating CEK template!\n");
        json_decref(jwe);
        free(b);
        return EXIT_FAILURE;
    }

    if (!jose_jwk_generate(cek)) {
        fprintf(stderr, "Error generating CEK!\n");
        json_decref(jwe);
        json_decref(cek);
        free(b);
        return EXIT_FAILURE;
    }

    if (!jose_jwe_encrypt(jwe, cek, b, l)) {
        fprintf(stderr, "Error encrypting input!\n");
        json_decref(jwe);
        json_decref(cek);
        free(b);
        return EXIT_FAILURE;
    }
    free(b);

    for (int i = 3; i < argc; i++) {
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            json_decref(jwe);
            json_decref(cek);
            return EXIT_FAILURE;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            json_decref(jwe);
            json_decref(cek);
            return EXIT_FAILURE;
        }

        if (!jose_jwe_seal(jwe, cek, jwk, NULL)) {
            fprintf(stderr, "Error creating seal!\n");
            json_decref(jwe);
            json_decref(jwk);
            json_decref(cek);
            return EXIT_FAILURE;
        }

        json_decref(jwk);
    }

    if (json_dumpf(jwe, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWS!\n");
        json_decref(jwe);
        json_decref(cek);
        return EXIT_FAILURE;
    }

    json_decref(cek);
    json_decref(jwe);
    return EXIT_SUCCESS;
}
