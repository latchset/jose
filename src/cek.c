/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "cek.h"
#include "cek_int.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

jose_cek_t *
cek_new(size_t len)
{
    jose_cek_t tmp = { len };
    jose_cek_t *out = NULL;

    out = malloc(sizeof(jose_cek_t) + len);
    if (!out)
        return NULL;

    memcpy(out, &tmp, sizeof(tmp));

    if (mlock(out->buf, out->len) != 0) {
        free(out);
        return NULL;
    }

    return out;
}

void
jose_cek_free(jose_cek_t *cek)
{
    if (!cek)
        return;

    memset(cek->buf, 0, cek->len);
    munlock(cek, cek->len);
    free(cek);
}
