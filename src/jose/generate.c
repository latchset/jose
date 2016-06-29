/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

int
jose_generate(int argc, char *argv[])
{
    json_t *jwk = NULL;

    jwk = json_loads(argv[2], 0, NULL);
    if (!jwk || !jose_jwk_generate(jwk)) {
        fprintf(stderr, "Invalid template!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwk, stdout, JSON_SORT_KEYS) == -1) {
        fprintf(stderr, "Error dumping JWK!\n");
        json_decref(jwk);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");
    json_decref(jwk);
    return EXIT_SUCCESS;
}
