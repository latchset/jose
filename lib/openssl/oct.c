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
#include "../hooks.h"

#include <string.h>
#include <openssl/rand.h>

static bool
jwk_make_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) < 0)
        return false;

    return strcmp(kty, "oct") == 0;
}

static bool
jwk_make_execute(jose_cfg_t *cfg, json_t *jwk)
{
    uint8_t key[KEYMAX] = {};
    json_int_t len = 0;

    if (!jwk_make_handles(cfg, jwk))
        return false;

    if (json_unpack(jwk, "{s:I}", "bytes", &len) < 0)
        return false;

    if (len > KEYMAX)
        return false;

    if (RAND_bytes(key, len) <= 0)
        return false;

    if (json_object_del(jwk, "bytes") < 0)
        return false;

    if (json_object_set_new(jwk, "k", jose_b64_enc(key, len)) < 0)
        return false;

    OPENSSL_cleanse(key, len);
    return true;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_MAKE,
        .make.handles = jwk_make_handles,
        .make.execute = jwk_make_execute
    };

    jose_hook_jwk_push(&jwk);
}
