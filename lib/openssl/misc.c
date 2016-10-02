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
        if (str && strcmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
}

BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_decode_json(const json_t *json)
{
    jose_buf_auto_t *buf = NULL;

    buf = jose_b64_decode_json(json);
    if (!buf)
        return NULL;

    return bn_decode(buf->data, buf->size);
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
    jose_buf_auto_t *buf = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    if ((int) len < BN_num_bytes(bn))
        return false;

    buf = jose_buf(len, JOSE_BUF_FLAG_WIPE);
    if (buf) {
        if (bn_encode(bn, buf->data, len))
            return jose_b64_encode_json(buf->data, len);
    }

    return NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    OpenSSL_add_all_algorithms();
    RAND_poll();
}
