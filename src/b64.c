/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"

#include <stdbool.h>
#include <string.h>

static const char table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

size_t
jose_b64_dlen(size_t elen)
{
    switch (elen % 4) {
    case 0: return elen / 4 * 3;
    case 2: return elen / 4 * 3 + 1;
    case 3: return elen / 4 * 3 + 2;
    default: return 0;
    }
}

size_t
jose_b64_elen(size_t dlen)
{
    switch (dlen % 3) {
    case 0: return dlen / 3 * 4;
    case 1: return dlen / 3 * 4 + 2;
    case 2: return dlen / 3 * 4 + 3;
    default: return 0;
    }
}

bool
jose_b64_decode(const char *enc, uint8_t dec[])
{
    uint8_t rem = 0;
    size_t len = 0;

    for (size_t i = 0; enc[i]; i++) {
        uint8_t v = 0;

        for (char c = enc[i]; v < sizeof(table) && table[v] != c; v++)
            continue;

        if (v >= sizeof(table))
            return false;

        switch (i % 4) {
        case 0:
            if (!enc[i+1])
                return false;

            rem = v << 2;
            break;

        case 1:
            dec[len++] = rem | (v >> 4);
            rem = v << 4;
            break;

        case 2:
            dec[len++] = rem | (v >> 2);
            rem = v << 6;
            break;

        case 3:
            dec[len++] = rem | v;
            break;
        }
    }

    return true;
}

bool
jose_b64_decode_json(const json_t *enc, uint8_t dec[])
{
    if (!json_is_string(enc))
        return false;

    return jose_b64_decode(json_string_value(enc), dec);
}

json_t *
jose_b64_decode_json_load(const json_t *enc, int flags)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    size_t len = 0;

    if (!json_is_string(enc))
        return NULL;

    len = jose_b64_dlen(json_string_length(enc));
    buf = malloc(len);
    if (!buf)
        return NULL;

    if (jose_b64_decode_json(enc, buf))
        out = json_loadb((char *) buf, len, flags, NULL);

    memset(buf, 0, len);
    free(buf);
    return out;
}

void
jose_b64_encode(const uint8_t dec[], size_t len, char enc[])
{
    uint8_t rem = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = dec[i];

        switch (i % 3) {
        case 0:
            *enc++ = table[c >> 2];
            *enc++ = table[rem = (c & 0x03) << 4];
            break;

        case 1:
            enc[-1] = table[rem | (c >> 4)];
            *enc++ = table[rem = (c & 0x0F) << 2];
            break;

        case 2:
            enc[-1] = table[rem | (c >> 6)];
            *enc++ = table[c & 0x3F];
            break;
        }
    }

    *enc = 0;
}

json_t *
jose_b64_encode_json(const uint8_t dec[], size_t len)
{
    json_t *json = NULL;
    char *buf = NULL;

    buf = malloc(jose_b64_elen(len) + 1);
    if (!buf)
        return NULL;

    jose_b64_encode(dec, len, buf);

    json = json_string(buf);
    free(buf);
    return json;
}

json_t *
jose_b64_encode_json_dump(const json_t *dec, int flags)
{
    json_t *out = NULL;
    char *buf = NULL;

    buf = json_dumps(dec, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
    if (!buf)
        return NULL;

    out = jose_b64_encode_json((uint8_t *) buf, strlen(buf));
    free(buf);
    return out;
}
