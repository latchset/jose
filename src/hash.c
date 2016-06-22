/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "hash.h"

#include <string.h>

bool
hash(const EVP_MD *md, uint8_t hsh[], ...)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned int ign = 0;
    bool ret = false;
    va_list ap;

    va_start(ap, hsh);

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto error;

    if (EVP_DigestInit(ctx, md) <= 0)
        goto error;

    for (const char *data = NULL; (data = va_arg(ap, const char *)); ) {
        if (EVP_DigestUpdate(ctx, (const uint8_t *) data, strlen(data)) <= 0)
            goto error;
    }

    ret = EVP_DigestFinal(ctx, hsh, &ign) > 0;

error:
    EVP_MD_CTX_destroy(ctx);
    va_end(ap);
    return ret;
}
