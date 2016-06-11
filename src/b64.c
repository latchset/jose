/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"
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

uint8_t *
jose_b64_decode(const json_t *json, size_t *len)
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

json_t *
jose_b64_decode_json(const json_t *json)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    size_t len = 0;

    buf = jose_b64_decode(json, &len);
    if (!buf)
        return NULL;

    out = json_loads((char *) buf, 0, NULL);
    free(buf);
    return NULL;
}

json_t *
jose_b64_encode(const uint8_t buf[], size_t len)
{
    json_t *json = NULL;
    char *tmp = NULL;

    if (!buf)
        return NULL;

    tmp = malloc((len + 2) / 3 * 4 + 1);
    if (!tmp)
        return NULL;

    b64url_enc(buf, len, tmp);

    json = json_string(tmp);
    free(tmp);
    return json;
}

json_t *
jose_b64_encode_json(const json_t *json)
{
    json_t *out = NULL;
    char *tmp = NULL;

    tmp = json_dumps(json, JSON_SORT_KEYS | JSON_COMPACT);
    if (!tmp)
        return NULL;

    out = jose_b64_encode((uint8_t *) tmp, strlen(tmp));
    free(tmp);
    return out;
}
