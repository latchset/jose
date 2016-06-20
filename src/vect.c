/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "vect.h"
#include "b64.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>

static const char *
filename(const char *name, const char *ext)
{
    static char tmp[PATH_MAX] = {};
    snprintf(tmp, sizeof(tmp) - 1, "vectors/%s.%s", name, ext);
    return tmp;
}

json_t *
vect_json(const char *name, const char *ext)
{
    json_t *out = NULL;
    FILE *file = NULL;

    file = fopen(filename(name, ext), "r");
    if (!file)
        return NULL;

    out = json_loadf(file, 0, NULL);
    fclose(file);
    return out;
}

jose_buf_t *
vect_buf(const char *name, const char *ext)
{
    jose_buf_t *buf = NULL;
    struct stat st = {};
    FILE *file = NULL;

    if (stat(filename(name, ext), &st) != 0)
        return NULL;

    buf = jose_buf_new(st.st_size, false);
    if (!buf)
        return NULL;

    file = fopen(filename(name, ext), "r");
    if (!file) {
        jose_buf_free(buf);
        return NULL;
    }

    buf->used = fread(buf->data, 1, buf->size, file);
    fclose(file);
    if (buf->used == 0) {
        jose_buf_free(buf);
        return NULL;
    }

    return buf;
}

char *
vect_str(const char *name, const char *ext)
{
    jose_buf_t *buf = NULL;
    char *out = NULL;

    buf = vect_buf(name, ext);
    if (!buf)
        return NULL;

    for (size_t i = 1; i <= buf->used; i++) {
        if (isspace(buf->data[buf->used - i]))
            buf->data[buf->used - i] = 0;
    }

    out = calloc(1, buf->used + 1);
    if (!out) {
        jose_buf_free(buf);
        return NULL;
    }

    memcpy(out, buf->data, buf->used);
    jose_buf_free(buf);

    return out;
}

jose_buf_t *
vect_b64(const char *name, const char *ext)
{
    char *str = NULL;
    jose_buf_t *dec = NULL;

    str = vect_str(name, ext);
    if (!str)
        return NULL;

    dec = jose_b64_decode_buf(str, false);
    free(str);
    return dec;
}
