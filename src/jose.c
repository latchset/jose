/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"
#include "jwk.h"
#include "jws.h"
#include "jwe.h"

#include <openssl/rand.h>

#include <argp.h>
#include <string.h>

static uint8_t *
load_all(FILE *file, size_t *len)
{
    static const size_t blocksize = 512;
    uint8_t *buf = NULL;

    for (size_t r = blocksize; r == blocksize; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(buf, *len + blocksize);
        if (!tmp) {
            free(buf);
            return NULL;
        }

        buf = tmp;
        r = fread(&buf[*len], 1, blocksize, stdin);
        *len += r;
    }

    return buf;
}

static json_t *
load_jose(FILE *file, json_t *(*conv)(const char *))
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    char *str = NULL;
    size_t len = 0;

    buf = load_all(file, &len);
    if (!buf)
        return NULL;

    str = calloc(1, len + 1);
    if (!str) {
        free(buf);
        return NULL;
    }

    memcpy(str, buf, len);
    free(buf);

    out = conv(str);
    if (!out)
        out = json_loads(str, 0, NULL);

    free(str);
    return out;
}

static size_t
str_to_enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
}

static int
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

static int
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

static int
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

static int
jose_verify(int argc, char *argv[])
{
    json_t *jws = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    jws = load_jose(stdin, jose_jws_from_compact);
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

static int
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

static int
jose_decrypt(int argc, char *argv[])
{
    json_t *jwe = NULL;

    if (argc < 3)
        return EXIT_FAILURE;

    jwe = load_jose(stdin, jose_jwe_from_compact);
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

int
main(int argc, char *argv[])
{
    if (argc < 2)
        goto usage;

    OpenSSL_add_all_algorithms();
    RAND_poll();

    switch(str_to_enum(argv[1], "generate", "publicize", "sign", "verify",
                       "encrypt", "decrypt", NULL)) {
    case 0: return jose_generate(argc, argv);
    case 1: return jose_publicize(argc, argv);
    case 2: return jose_sign(argc, argv);
    case 3: return jose_verify(argc, argv);
    case 4: return jose_encrypt(argc, argv);
    case 5: return jose_decrypt(argc, argv);
    }

usage:
    fprintf(stderr, "Usage:\n");
    return EXIT_FAILURE;
}
