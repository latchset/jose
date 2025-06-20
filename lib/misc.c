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
#include <string.h>
#include "hooks.h"

bool
encode_protected(json_t *obj)
{
    json_t *p = NULL;

    if (json_unpack(obj, "{s?o}", "protected", &p) == -1)
        return false;

    if (!p || json_is_string(p))
        return true;

    if (!json_is_object(p))
        return false;

    return json_object_set_new(obj, "protected", jose_b64_enc_dump(p)) == 0;
}

void
zero(void *mem, size_t len)
{
    memset(mem, 0, len);
}


bool
handle_zip_enc(json_t *json, const void *in, size_t len, void **data, size_t *datalen)
{
    json_auto_t *prt = NULL;
    char *z = NULL;
    const jose_hook_alg_t *a = NULL;
    jose_io_auto_t *zip = NULL;
    jose_io_auto_t *zipdata = NULL;

    prt = json_object_get(json, "protected");
    if (prt && json_is_string(prt))
        prt = jose_b64_dec_load(prt);

    /* Check if we have "zip" in the protected header. */
    if (json_unpack(prt, "{s:s}", "zip", &z) == -1) {
        /* No zip. */
        *data = (void*)in;
        *datalen = len;
        return true;
    }

    /* OK, we have "zip", so we should compress the payload before
     * the encryption takes place. */
    a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_COMP, z);
    if (!a)
        return false;

    zipdata = jose_io_malloc(NULL, data, datalen);
    if (!zipdata)
        return false;

    zip = a->comp.def(a, NULL, zipdata);
    if (!zip || !zip->feed(zip, in, len) || !zip->done(zip))
        return false;

    return true;
}

bool
zip_in_protected_header(json_t *json)
{
    json_auto_t *prt = NULL;
    char *z = NULL;

    prt = json_object_get(json, "protected");
    if (prt && json_is_string(prt))
        prt = jose_b64_dec_load(prt);

    /* Check if we have "zip" in the protected header. */
    if (json_unpack(prt, "{s:s}", "zip", &z) == -1)
        return false;

    /* We have "zip", but let's validate the alg also. */
    return jose_hook_alg_find(JOSE_HOOK_ALG_KIND_COMP, z) != NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    json_object_seed(0);
}
