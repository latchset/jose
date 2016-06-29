/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

int
jose_sign(int argc, char *argv[])
{
    json_t *jws = NULL;
    uint8_t *b = NULL;
    size_t l = 0;

    if (argc < 4)
        return EXIT_FAILURE;

    jws = json_loads(argv[2], 0, NULL);
    if (!jws) {
        fprintf(stderr, "Invalid template!\n");
        return EXIT_FAILURE;
    }

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(b, l + 512);
        if (!tmp) {
            fprintf(stderr, "Out of memory!\n");
            json_decref(jws);
            return EXIT_FAILURE;
        }

        b = tmp;
        r = fread(&b[l], 1, 512, stdin);
        l += r;
    }

    if (json_object_set_new(jws, "payload", jose_b64_encode_json(b, l)) < 0) {
        fprintf(stderr, "Error encoding payload!\n");
        json_decref(jws);
        return EXIT_FAILURE;
    }

    for (int i = 3; i < argc; i++) {
        json_t *jwk = NULL;
        FILE *file = NULL;

        file = fopen(argv[i], "r");
        if (!file) {
            fprintf(stderr, "Unable to open: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        jwk = json_loadf(file, 0, NULL);
        fclose(file);
        if (!jwk) {
            fprintf(stderr, "Invalid JWK: %s!\n", argv[i]);
            json_decref(jws);
            return EXIT_FAILURE;
        }

        if (!jose_jws_sign(jws, jwk, NULL)) {
            fprintf(stderr, "Error creating signature!\n");
            json_decref(jws);
            json_decref(jwk);
            return EXIT_FAILURE;
        }

        json_decref(jwk);
    }

    if (json_dumpf(jws, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWS!\n");
        json_decref(jws);
        return EXIT_FAILURE;
    }

    json_decref(jws);
    return EXIT_SUCCESS;
}
