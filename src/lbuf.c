/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "lbuf.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

lbuf_t *
lbuf_new(size_t len)
{
    lbuf_t tmp = { len };
    lbuf_t *out = NULL;

    out = malloc(sizeof(lbuf_t) + len);
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
lbuf_free(lbuf_t *lbuf)
{
    if (!lbuf)
        return;

    memset(lbuf->buf, 0, lbuf->len);
    munlock(lbuf, lbuf->len);
    free(lbuf);
}
