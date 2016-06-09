/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "json.h"

#include <stdbool.h>
#include <string.h>

static const char table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

static void
b64url_enc(const jose_key_t *key, char b64[])
{
    uint8_t rem = 0;

    for (size_t i = 0; i < key->len; i++) {
        uint8_t c = key->key[i];

        switch (i % 3) {
        case 0:
            *b64++ = table[c >> 2];
            *b64++ = table[rem = (c & 0x03) << 4];
            break;

        case 1:
            b64[-1] = table[rem | (c >> 4)];
            *b64++ = table[rem = (c & 0x0F) << 2];
            break;

        case 2:
            b64[-1] = table[rem | (c >> 6)];
            *b64++ = table[c & 0x3F];
            break;
        }
    }

    *b64 = 0;
}

static bool
b64url_dec(const char b64[], jose_key_t *key)
{
    uint8_t rem = 0;

    key->len = 0;

    for (size_t i = 0; b64[i]; i++) {
        uint8_t v = 0;

        for (char c = b64[i]; v < sizeof(table) && table[v] != c; v++)
            continue;

        if (v >= sizeof(table))
            return false;

        switch (i % 4) {
        case 0:
            if (!b64[i+1])
                return false;

            rem = v << 2;
            break;

        case 1:
            key->key[key->len++] = rem | (v >> 4);
            rem = v << 4;
            break;

        case 2:
            key->key[key->len++] = rem | (v >> 2);
            rem = v << 6;
            break;

        case 3:
            key->key[key->len++] = rem | v;
            break;
        }
    }

    return true;
}

jose_key_t *
json_to_key(const json_t *json)
{
    jose_key_t *key = NULL;

    if (!json_is_string(json))
        return NULL;

    key = jose_key_new((json_string_length(json) + 3) / 4 * 3);
    if (!key)
        return NULL;

    if (b64url_dec(json_string_value(json), key))
        return key;

    jose_key_free(key);
    return NULL;
}

json_t *
json_from_key(const jose_key_t *key)
{
    json_t *json = NULL;
    char *buf = NULL;

    buf = malloc((key->len + 2) / 3 * 4 + 1);
    if (!buf)
        return NULL;

    b64url_enc(key, buf);

    json = json_string(buf);
    free(buf);
    return json;
}

BIGNUM *
json_to_bn(const json_t *json)
{
    jose_key_t *key = NULL;
    BIGNUM *bn = NULL;

    if (!json_is_string(json))
        return NULL;

    key = json_to_key(json);
    if (!key)
        return NULL;

    bn = BN_bin2bn(key->key, key->len, NULL);
    jose_key_free(key);
    return bn;
}

json_t *
json_from_bn(const BIGNUM *bn, size_t len)
{
    jose_key_t *key = NULL;
    json_t *json = NULL;
    int bytes = 0;

    if (!bn || len <= 0)
        return NULL;

    bytes = BN_num_bytes(bn);
    if (bytes < 0 || bytes > (int) len)
        return NULL;

    key = jose_key_new(len);
    if (!key)
        return NULL;

    memset(key->key, 0, key->len);

    len = BN_bn2bin(bn, &key->key[key->len - bytes]);
    if (len > 0)
        json = json_from_key(key);

    jose_key_free(key);
    return json;
}

