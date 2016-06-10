/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "json.h"

#include <string.h>

json_t *
jose_jwk_from_key(const jose_key_t *key)
{
    return json_pack("{s:s, s:o}", "kty", "oct", "k", json_from_key(key));
}

jose_key_t *
jose_jwk_to_key(const json_t *jwk)
{
    const char *kty = NULL;
    json_t *k = NULL;

    if (json_unpack((json_t *) jwk, "{s:s, s:o}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    return json_to_key(k);
}

