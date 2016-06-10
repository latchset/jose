/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

#include <sys/mman.h>
#include <stddef.h>
#include <string.h>

jose_key_t *
jose_key_new(size_t len)
{
    jose_key_t *key = NULL;

    key = malloc(offsetof(jose_key_t, key) + len);
    if (!key)
        return NULL;

    if (mlock(key, offsetof(jose_key_t, key) + len) == -1) {
        free(key);
        return NULL;
    }

    key->len = len;
    return key;
}

void
jose_key_free(jose_key_t *key)
{
    if (key) {
        memset(key, 0, offsetof(jose_key_t, key) + key->len);
        munlock(key, offsetof(jose_key_t, key) + key->len);
    }

    free(key);
}

