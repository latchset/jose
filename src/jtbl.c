/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jtbl.h"
#include <string.h>

bool
jtbl_is_end(const jtbl_value_t *val)
{
    static const jtbl_value_t end = {};
    return memcmp(val, &end, sizeof(end)) == 0;
}

json_t *
jtbl_make(const jtbl_value_t *val)
{
    json_t *out = NULL;

    if (!val)
        return NULL;

    switch (val->type) {
    case JSON_INTEGER: return json_integer(val->i);
    case JSON_STRING: return json_string(val->s);
    case JSON_FALSE: return json_false();
    case JSON_TRUE: return json_true();
    case JSON_NULL: return json_null();
    case JSON_REAL: return json_real(val->r);

    case JSON_OBJECT:
        out = json_object();
        if (!out)
            return NULL;

        for (size_t i = 0; val->o && val->o[i].k; i++) {
            json_t *tmp = jtbl_make(&val->o[i].v);
            if (json_object_set_new(out, val->o[i].k, tmp) == -1) {
                json_decref(out);
                return NULL;
            }
        }

        return out;

    case JSON_ARRAY:
        out = json_array();
        if (!out)
            return NULL;

        for (size_t i = 0; val->a && !jtbl_is_end(&val->a[i]); i++) {
            if (json_array_append_new(out, jtbl_make(&val->a[i])) == -1) {
                json_decref(out);
                return NULL;
            }
        }

        return out;

    default: return NULL;
    }
}
