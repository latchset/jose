/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

#include <sys/mman.h>
#include <stddef.h>
#include <string.h>

struct jose_key *
jose_key_new(size_t len)
{
    struct jose_key *key = NULL;

    key = malloc(offsetof(struct jose_key, key) + len);
    if (!key)
        return NULL;

    if (mlock(key, offsetof(struct jose_key, key) + len) == -1) {
        free(key);
        return NULL;
    }

    key->len = len;
    return key;
}

void
jose_key_free(struct jose_key *key)
{
    if (key) {
        memset(key, 0, offsetof(struct jose_key, key) + key->len);
        munlock(key, offsetof(struct jose_key, key) + key->len);
    }

    free(key);
}

