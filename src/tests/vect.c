/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "vect.h"
#include "../b64.h"

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

char *
vect_str(const char *name, const char *ext)
{
    struct stat st = {};
    FILE *file = NULL;
    char *buf = NULL;
    size_t len = 0;

    if (stat(filename(name, ext), &st) != 0)
        return NULL;

    buf = calloc(1, st.st_size + 1);
    if (!buf)
        return NULL;

    file = fopen(filename(name, ext), "r");
    if (!file) {
        free(buf);
        return NULL;
    }

    len = fread(buf, 1, st.st_size, file);
    fclose(file);
    if (len == 0) {
        free(buf);
        return NULL;
    }

    for (size_t i = 1; i <= len; i++) {
        if (isspace(buf[len - i]))
            buf[len - i] = 0;
    }

    return buf;
}
