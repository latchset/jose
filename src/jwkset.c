/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwkset.h"
#include "jwk.h"

json_t *
jose_jwkset_copy(const json_t *jwkset, bool prv)
{
    const json_t *keys = NULL;
    json_t *copy = NULL;

    keys = json_is_array(jwkset) ? jwkset : json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        return NULL;

    copy = json_array();
    if (!json_is_array(copy))
        return NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        const json_t *k = json_array_get(keys, i);

        if (json_array_append_new(copy, jose_jwk_dup(k, prv)) == -1)
            goto error;
    }

    return json_pack("{s: o}", "keys", copy);

error:
    json_decref(copy);
    return NULL;
}
