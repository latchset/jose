/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "buf.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

struct buf {
    size_t locked;
    buf_t buf;
};

buf_t *
buf_new(size_t len, bool lock)
{
    struct buf *out = NULL;

    out = malloc(sizeof(struct buf) + len);
    if (!out)
        goto error;

    if (lock && mlock(out->buf.buf, len) != 0)
        goto error;

    out->locked = lock ? len : 0;
    out->buf.len = len;
    return &out->buf;

error:
    free(out);
    return NULL;
}

void
buf_free(buf_t *key)
{
    struct buf *tmp = NULL;

    if (!key)
        return;

    tmp = (struct buf *) ((char *) key - offsetof(struct buf, buf));
    if (tmp->locked > 0) {
        memset(tmp->buf.buf, 0, tmp->locked);
        munlock(tmp, tmp->locked);
    }

    free(tmp);
}
