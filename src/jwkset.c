/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwkset.h"

static const char *jwkprv[] = {
    "k", "d", "p", "q", "dp", "dq", "qi", "oth", NULL
};

json_t *
jose_jwkset_private(const json_t *jwkset)
{
    json_t *copy = NULL;

    copy = json_deep_copy(jwkset);

    if (json_is_array(copy))
        copy = json_pack("{s:o}", "keys", copy);

    if (!json_is_object(copy))
        goto error;

    return copy;

error:
    json_decref(copy);
    return NULL;
}

json_t *
jose_jwkset_public(const json_t *jwkset)
{
    const json_t *array = NULL;
    json_t *copy = NULL;

    copy = jose_jwkset_private(jwkset);
    if (!copy)
        return NULL;

    array = json_object_get(copy, "keys");
    if (!json_is_array(array))
        goto error;

    for (size_t i = 0; i < json_array_size(array); i++) {
        json_t *jwk = json_array_get(array, i);

        if (!json_is_object(jwk))
            continue;

        for (size_t j = 0; jwkprv[j]; j++) {
            if (json_object_get(jwk, jwkprv[j]) &&
                json_object_del(jwk, jwkprv[j]) == -1)
                goto error;
        }
    }

    return copy;

error:
    json_decref(copy);
    return NULL;
}

