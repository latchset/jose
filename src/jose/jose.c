/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"
#include <openssl/rand.h>
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

json_t *
load_compact(FILE *file, json_t *(*conv)(const char *))
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
