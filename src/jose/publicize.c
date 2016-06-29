/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

int
jose_publicize(int argc, char *argv[])
{
    json_t *jwk = NULL;

    jwk = json_loadf(stderr, 0, NULL);
    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (!jose_jwk_publicize(jwk)) {
        fprintf(stderr, "Error removing public keys!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwk, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    json_decref(jwk);
    return EXIT_SUCCESS;
}
