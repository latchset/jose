/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include "b64.h"

#include <string.h>

json_t *
compact_to_obj(const char *compact, ...)
{
    json_t *out = NULL;
    size_t count = 0;
    size_t c = 0;
    va_list ap;

    if (!compact)
        return NULL;

    va_start(ap, compact);
    while (va_arg(ap, const char *))
        count++;
    va_end(ap);

    size_t len[count];

    memset(len, 0, sizeof(len));

    for (size_t i = 0; compact[i]; i++) {
        if (compact[i] != '.')
            len[c]++;
        else if (++c > count - 1)
            return NULL;
    }

    if (c != count - 1)
        return NULL;

    out = json_object();
    if (!out)
        return NULL;

    c = 0;
    va_start(ap, compact);
    for (size_t i = 0; i < count; i++) {
        json_t *val = json_stringn(&compact[c], len[i]);
        if (json_object_set_new(out, va_arg(ap, const char *), val) < 0) {
            json_decref(out);
            va_end(ap);
            return NULL;
        }

        c += len[i] + 1;
    }
    va_end(ap);

    if (json_object_size(out) == 0) {
        json_decref(out);
        return NULL;
    }

    return out;
}

bool
set_protected_new(json_t *obj, const char *key, json_t *val)
{
    json_t *p = NULL;
    bool ret = false;

    if (json_unpack(obj, "{s? O}", "protected", &p) == -1)
        goto egress;

    if (!p)
        p = json_object();

    if (json_is_string(p)) {
        json_t *tmp = jose_b64_decode_json_load(p);
        json_decref(p);
        p = tmp;
    }

    if (!json_is_object(p))
        goto egress;

    if (json_object_set(p, key, val) == -1)
        goto egress;

    ret = json_object_set(obj, "protected", p) == 0;

egress:
    json_decref(val);
    json_decref(p);
    return ret;
}

const char *
encode_protected(json_t *obj)
{
    json_t *p = NULL;

    if (json_unpack(obj, "{s?o}", "protected", &p) == -1)
        return NULL;

    if (!p)
        return "";

    if (json_is_string(p))
        return json_string_value(p);

    if (!json_is_object(p))
        return NULL;

    p = jose_b64_encode_json_dump(p);
    if (!p)
        return NULL;

    if (json_object_set_new(obj, "protected", p) == -1)
        return NULL;

    return json_string_value(p);
}

bool
add_entity(json_t *root, json_t *obj, const char *plural, ...)
{
    bool found = false;
    json_t *pl = NULL;
    va_list ap;

    pl = json_object_get(root, plural);
    if (pl) {
        if (!json_is_array(pl))
            return false;

        if (json_array_size(pl) == 0) {
            if (json_object_del(root, plural) == -1)
                return false;

            pl = NULL;
        }
    }

    va_start(ap, plural);
    for (const char *key; (key = va_arg(ap, const char *)); ) {
        if (json_object_get(root, key))
            found = true;
    }
    va_end(ap);

    /* If we have flattened format, migrate to general format. */
    if (found) {
        json_t *o = NULL;

        if (!pl) {
            pl = json_array();
            if (json_object_set_new(root, plural, pl) == -1)
                return false;
        }

        o = json_object();
        if (json_array_append_new(pl, o) == -1)
            return false;

        va_start(ap, plural);
        for (const char *key; (key = va_arg(ap, const char *)); ) {
            json_t *tmp = NULL;

            tmp = json_object_get(root, key);
            if (tmp) {
                if (json_object_set(o, key, tmp) == -1 ||
                    json_object_del(root, key) == -1) {
                    va_end(ap);
                    return false;
                }
            }
        }
        va_end(ap);
    }

    /* If we have some signatures already, append to the array. */
    if (pl)
        return json_array_append(pl, obj) == 0;

    return json_object_update(root, obj) == 0;
}

