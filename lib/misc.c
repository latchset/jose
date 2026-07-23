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

#define _GNU_SOURCE
#include "misc.h"
#include <jose/b64.h>
#include <jose/cfg.h>
#include <openssl/crypto.h>
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
    OPENSSL_cleanse(mem, len);
}

/* Decode the base64url-encoded protected header and load it as JSON only
 * when it can contain a "zip" key. The full JSON parse is the expensive
 * step (the base64url decode is comparatively cheap), so we gate it behind
 * a substring scan for "zip" over the *decoded* bytes: a "zip" key is only
 * possible if the literal bytes "zip" appear in the decoded JSON text.
 *
 * The scan must run on the decoded bytes, NOT on the base64url-encoded
 * string: a "zip" key does not survive base64url encoding as the literal
 * substring "zip", so scanning the encoded form yields false negatives.
 *
 * When "zip" is definitely absent, *no_zip is set to true and NULL is
 * returned without parsing. On decode error, *no_zip stays false and NULL
 * is returned (callers then treat it the same as a header with no zip). */
static json_t *
load_protected_check_zip(const json_t *prt, bool *no_zip)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    size_t size = 0;

    *no_zip = false;

    size = jose_b64_dec(prt, NULL, 0);
    if (size == SIZE_MAX)
        return NULL;

    buf = jose_calloc(1, size);
    if (!buf)
        return NULL;

    if (jose_b64_dec(prt, buf, size) != size) {
        zero(buf, size);
        jose_free(buf);
        return NULL;
    }

    if (memmem(buf, size, "zip", 3))
        out = json_loadb((char *) buf, size, JSON_DECODE_ANY, NULL);
    else
        *no_zip = true;

    zero(buf, size);
    jose_free(buf);
    return out;
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
    if (prt && json_is_string(prt)) {
        bool no_zip = false;
        json_t *loaded = load_protected_check_zip(prt, &no_zip);
        if (no_zip) {
            /* No zip; skip the full parse. (prt is a borrowed reference,
             * so clear it before returning to avoid a spurious decref.) */
            prt = NULL;
            *data = (void*)in;
            *datalen = len;
            return true;
        }
        prt = loaded;
    }

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
    if (prt && json_is_string(prt)) {
        bool no_zip = false;
        json_t *loaded = load_protected_check_zip(prt, &no_zip);
        if (no_zip) {
            /* No zip; skip the full parse. (prt is a borrowed reference,
             * so clear it before returning to avoid a spurious decref.) */
            prt = NULL;
            return false;
        }
        prt = loaded;
    }

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
