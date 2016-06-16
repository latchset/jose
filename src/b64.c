/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"
#include "lbuf.h"

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
    const char *e = NULL;
    json_t *out = NULL;
    lbuf_t *lbuf = NULL;

    if (json_unpack((json_t *) enc, "s", &e) == -1)
        return NULL;

    lbuf = lbuf_new(jose_b64_dlen(strlen(e)));
    if (!lbuf)
        return NULL;

    if (jose_b64_decode(e, lbuf->buf))
        out = json_loadb((char *) lbuf->buf, lbuf->len, flags, NULL);

    lbuf_free(lbuf);
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
    lbuf_t *lbuf = NULL;

    lbuf = lbuf_new(jose_b64_elen(len) + 1);
    if (!lbuf)
        return NULL;

    jose_b64_encode(dec, len, (char *) lbuf->buf);

    json = json_string((char *) lbuf->buf);
    lbuf_free(lbuf);
    return json;
}

static int
callback(const char *buffer, size_t size, void *data)
{
    lbuf_t **lbuf = data;
    lbuf_t *tmp = NULL;
    size_t off = 0;

    if (*lbuf)
        off = (*lbuf)->len;

    tmp = lbuf_new(size + off);
    if (!tmp)
        return -1;

    if (*lbuf)
        memcpy(tmp->buf, (*lbuf)->buf, off);

    memcpy(tmp->buf + off, buffer, size);
    lbuf_free(*lbuf);
    *lbuf = tmp;
    return 0;
}


json_t *
jose_b64_encode_json_dump(const json_t *dec, int flags)
{
    json_t *out = NULL;
    lbuf_t *lbuf = NULL;

    if (json_dump_callback(dec, callback, &lbuf, flags) == -1)
        return NULL;

    out = jose_b64_encode_json(lbuf->buf, lbuf->len);
    lbuf_free(lbuf);
    return out;
}
