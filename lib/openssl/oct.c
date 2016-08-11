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
#include <jose/jwk.h>
#include <openssl/rand.h>

static bool
generate(json_t *jwk)
{
    json_int_t len = 0;
    uint8_t *buf = NULL;

    if (json_unpack(jwk, "{s:i}", "bytes", &len) == -1)
        return false;

    buf = malloc(len);
    if (!buf)
        return false;

    if (RAND_bytes(buf, len) <= 0) {
        clear_free(buf, len);
        return false;
    }

    if (json_object_set_new(jwk, "k", jose_b64_encode_json(buf, len)) == -1) {
        clear_free(buf, len);
        return false;
    }
    clear_free(buf, len);

    return json_object_del(jwk, "bytes") == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .kty = "oct",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
