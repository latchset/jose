/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

jose_key_t *
jose_key_new(size_t len)
{
    jose_key_t *key = NULL;

    key = malloc(offsetof(jose_key_t, key) + len);
    if (!key)
        goto error;

    if (mlock(key, offsetof(jose_key_t, key) + len) != 0)
        goto error;

    key->len = len;
    return key;

error:
    free(key);
    return NULL;
}

void
jose_key_free(jose_key_t *key)
{
    if (key) {
        size_t len = offsetof(jose_key_t, key) + key->len;
        memset(key, 0, len);
        munlock(key, len);
    }

    free(key);
}
