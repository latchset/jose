/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "json.h"

#include <stdbool.h>
#include <string.h>

static const char table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

static void
b64url_enc(const uint8_t buf[], size_t len, char b64[])
{
    uint8_t rem = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];

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
b64url_dec(const char b64[], uint8_t buf[], size_t *len)
{
    uint8_t rem = 0;

    *len = 0;

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
            buf[(*len)++] = rem | (v >> 4);
            rem = v << 4;
            break;

        case 2:
            buf[(*len)++] = rem | (v >> 2);
            rem = v << 6;
            break;

        case 3:
            buf[(*len)++] = rem | v;
            break;
        }
    }

    return true;
}

BIGNUM *
json_to_bn(const json_t *json)
{
    struct jose_key *key = NULL;
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

uint8_t *
json_to_buf(const json_t *json, size_t *len)
{
    uint8_t *buf = NULL;

    if (!json_is_string(json))
        return NULL;

    buf = malloc((json_string_length(json) + 3) / 4 * 3);
    if (!buf)
        return NULL;

    if (b64url_dec(json_string_value(json), buf, len))
        return buf;

    free(buf);
    return NULL;
}

struct jose_key *
json_to_key(const json_t *json)
{
    struct jose_key *key = NULL;

    if (!json_is_string(json))
        return NULL;

    key = jose_key_new((json_string_length(json) + 3) / 4 * 3);
    if (!key)
        return NULL;

    if (b64url_dec(json_string_value(json), key->key, &key->len))
        return key;

    jose_key_free(key);
    return NULL;
}

json_t *
json_from_bn(const BIGNUM *bn, size_t len)
{
    struct jose_key *key = NULL;
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

json_t *
json_from_buf(const uint8_t buf[], size_t len)
{
    json_t *json = NULL;
    char *tmp = NULL;

    tmp = malloc((len + 2) / 3 * 4 + 1);
    if (!tmp)
        return NULL;

    b64url_enc(buf, len, tmp);

    json = json_string(tmp);
    free(tmp);
    return json;
}

json_t *
json_from_key(const struct jose_key *key)
{
    json_t *json = NULL;
    char *buf = NULL;

    buf = malloc((key->len + 2) / 3 * 4 + 1);
    if (!buf)
        return NULL;

    b64url_enc(key->key, key->len, buf);

    json = json_string(buf);
    free(buf);
    return json;
}
