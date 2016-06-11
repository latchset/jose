/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include <string.h>

json_t *
jose_jws_from_compact(const char *jws)
{
    size_t len[3] = { 0, 0, 0 };

    for (size_t c = 0, i = 0; jws[i]; i++) {
        if (jws[i] != '.')
            len[c]++;
        else if (++c > 2)
            return NULL;
    }

    if (len[0] == 0 || len[1] == 0 || len[2] == 0)
        return NULL;

    return json_pack("{s: s%, s: s%, s: s%}",
                     "payload", &jws[len[0] + 1], len[1],
                     "protected", jws, len[0],
                     "signature", &jws[len[0] + len[1] + 2], len[2]);
}

char *
jose_jws_to_compact(const json_t *jws)
{
    const char *signature = NULL;
    const char *protected = NULL;
    const char *payload = NULL;
    const char *header = NULL;
    char *out = NULL;

    if (json_unpack((json_t *) jws, "{s: s, s: s, s: s, s? s}",
                    "payload", &payload,
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1 &&
        json_unpack((json_t *) jws, "{s: s, s: [{s: s, s: s, s: s, s? s}!]}",
                    "payload", &payload,
                    "signatures",
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1)
        return NULL;

    if (header)
        return NULL;

    asprintf(&out, "%s.%s.%s", protected, payload, signature);
    return out;
}

bool
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              const json_t *jwks)
{
    const json_t *array = NULL;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (array) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *jwk = json_array_get(array, i);

            if (!jose_jws_sign(jws, head, prot, jwk))
                return false;
        }

        return true;
    }

#warning TODO
}

bool
jose_jws_verify(const json_t *jws, const json_t *jwks, bool all)
{
#warning TODO
    return false;
}
