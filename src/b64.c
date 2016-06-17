/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"
#include "buf.h"

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

jose_buf_t *
jose_b64_decode_buf(const char *enc, bool lock)
{
    jose_buf_t *buf = NULL;

    buf = jose_buf_new(jose_b64_dlen(strlen(enc)), lock);
    if (!buf)
        return NULL;

    if (!jose_b64_decode(enc, buf->data)) {
        jose_buf_free(buf);
        return NULL;
    }

    return buf;
}

bool
jose_b64_decode_json(const json_t *enc, uint8_t dec[])
{
    if (!json_is_string(enc))
        return false;

    return jose_b64_decode(json_string_value(enc), dec);
}

jose_buf_t *
jose_b64_decode_json_buf(const json_t *enc, bool lock)
{
    if (!json_is_string(enc))
        return NULL;

    return jose_b64_decode_buf(json_string_value(enc), lock);
}

json_t *
jose_b64_decode_json_load(const json_t *enc, int flags)
{
    json_t *out = NULL;
    jose_buf_t *buf = NULL;

    buf = jose_b64_decode_json_buf(enc, true);
    if (buf)
        out = json_loadb((char *) buf->data, buf->used, flags, NULL);

    jose_buf_free(buf);
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

void
jose_b64_encode_buf(const jose_buf_t *dec, char enc[])
{
    return jose_b64_encode(dec->data, dec->used, enc);
}

json_t *
jose_b64_encode_json(const uint8_t dec[], size_t len)
{
    json_t *json = NULL;
    jose_buf_t *buf = NULL;

    buf = jose_buf_new(jose_b64_elen(len) + 1, true);
    if (!buf)
        return NULL;

    jose_b64_encode(dec, len, (char *) buf->data);

    json = json_string((char *) buf->data);
    jose_buf_free(buf);
    return json;
}

json_t *
jose_b64_encode_json_buf(const jose_buf_t *dec)
{
    return jose_b64_encode_json(dec->data, dec->used);
}

static int
callback(const char *buffer, size_t size, void *data)
{
    jose_buf_t **buf = data;
    jose_buf_t *tmp = NULL;
    size_t off = 0;

    if (*buf)
        off = (*buf)->size;

    tmp = jose_buf_new(size + off, true);
    if (!tmp)
        return -1;

    if (*buf)
        memcpy(tmp->data, (*buf)->data, off);

    memcpy(&tmp->data[off], buffer, size);
    jose_buf_free(*buf);
    *buf = tmp;
    return 0;
}


json_t *
jose_b64_encode_json_dump(const json_t *dec, int flags)
{
    json_t *out = NULL;
    jose_buf_t *buf = NULL;

    if (json_dump_callback(dec, callback, &buf, flags) == -1)
        return NULL;

    out = jose_b64_encode_json(buf->data, buf->used);
    jose_buf_free(buf);
    return out;
}
