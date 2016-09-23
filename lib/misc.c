/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc.h"
#include <jose/b64.h>

#include <ctype.h>
#include <string.h>

bool
set_protected_new(json_t *obj, const char *key, json_t *val)
{
    json_auto_t __attribute__((unused)) *scope = val; /* Steal reference */
    json_auto_t *p = NULL;

    if (json_unpack(obj, "{s? O}", "protected", &p) == -1)
        return false;

    if (!p)
        p = json_object();

    if (json_is_string(p)) {
        json_t *tmp = jose_b64_decode_json_load(p);
        p = tmp;
    }

    if (!json_is_object(p))
        return false;

    if (json_object_set(p, key, val) == -1)
        return false;

    return json_object_set(obj, "protected", p) == 0;
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

