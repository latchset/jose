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
#include <openssl/rand.h>

size_t
str2enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0) {
            va_end(ap);
            return i;
        }
    }

    va_end(ap);
    return SIZE_MAX;
}

BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_decode_json(const json_t *json)
{
    uint8_t *tmp = NULL;
    BIGNUM *bn = NULL;
    size_t len = 0;

    len = jose_b64_dec(json, NULL, 0);
    if (len == SIZE_MAX)
        return NULL;

    tmp = calloc(1, len);
    if (!tmp)
        return NULL;

    if (jose_b64_dec(json, tmp, len) != len) {
        free(tmp);
        return NULL;
    }

    bn = bn_decode(tmp, len);
    OPENSSL_cleanse(tmp, len);
    free(tmp);
    return bn;
}

bool
bn_encode(const BIGNUM *bn, uint8_t buf[], size_t len)
{
    int bytes = 0;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    bytes = BN_num_bytes(bn);
    if (bytes < 0 || bytes > (int) len)
        return false;

    memset(buf, 0, len);
    return BN_bn2bin(bn, &buf[len - bytes]) > 0;
}

json_t *
bn_encode_json(const BIGNUM *bn, size_t len)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;

    if (!bn)
        return NULL;

    if (len == 0)
        len = BN_num_bytes(bn);

    if ((int) len < BN_num_bytes(bn))
        return NULL;

    buf = calloc(1, len);
    if (!buf)
        return NULL;

    if (bn_encode(bn, buf, len)) {
        out = jose_b64_enc(buf, len);
        OPENSSL_cleanse(buf, len);
    }

    free(buf);
    return out;
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

static void __attribute__((constructor))
constructor(void)
{
    OpenSSL_add_all_algorithms();
    RAND_poll();
}
