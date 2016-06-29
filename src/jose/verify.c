/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"
#include <string.h>

int
jose_verify(int argc, char *argv[])
{
    json_t *jws = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    jws = load_compact(stdin, jose_jws_from_compact);
    if (!jws)
        return EXIT_FAILURE;

    for (int i = 2; i < argc; i++) {
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

        if (jose_jws_verify(jws, jwk)) {
            const char *payload = NULL;
            uint8_t *out = NULL;
            size_t len = 0;

            json_decref(jwk);

            if (json_unpack(jws, "{s:s}", "payload", &payload) < 0) {
                json_decref(jws);
                return EXIT_FAILURE;
            }

            len = jose_b64_dlen(strlen(payload));
            out = malloc(len);
            if (!out) {
                json_decref(jws);
                return EXIT_FAILURE;
            }

            if (!jose_b64_decode(payload, out)) {
                json_decref(jws);
                free(out);
                return EXIT_FAILURE;
            }

            fwrite(out, 1, len, stdout);
            json_decref(jws);
            free(out);
            return EXIT_SUCCESS;
        }

        json_decref(jwk);
    }

    fprintf(stderr, "No signatures validated!\n");
    json_decref(jws);
    return EXIT_FAILURE;
}
