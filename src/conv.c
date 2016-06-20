/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "conv.h"
#include "b64.h"

#include <openssl/evp.h>
#include <string.h>

BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_decode_buf(const jose_buf_t *buf)
{
    return BN_bin2bn(buf->data, buf->used, NULL);
}

BIGNUM *
bn_decode_json(const json_t *json)
{
    jose_buf_t *buf = NULL;
    BIGNUM *bn = NULL;

    buf = jose_b64_decode_buf(json_string_value(json), true);
    if (buf)
        bn = bn_decode(buf->data, buf->used);

    jose_buf_free(buf);
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

jose_buf_t *
bn_encode_buf(const BIGNUM *bn, size_t len)
{
    jose_buf_t *buf = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    buf = jose_buf_new(len, true);
    if (buf) {
        if (bn_encode(bn, buf->data, buf->used))
            return buf;

        jose_buf_free(buf);
    }

    return NULL;
}

json_t *
bn_encode_json(const BIGNUM *bn, size_t len)
{
    json_t *out = NULL;
    jose_buf_t *buf = NULL;

    buf = bn_encode_buf(bn, len);
    if (!buf)
        return NULL;

    out = jose_b64_encode_json_buf(buf);
    jose_buf_free(buf);
    return out;
}

json_t *
compact_to_obj(const char *compact, ...)
{
    json_t *out = NULL;
    size_t count = 0;
    size_t c = 0;
    va_list ap;

    if (!compact)
        return NULL;

    va_start(ap, compact);
    while (va_arg(ap, const char *))
        count++;
    va_end(ap);

    size_t len[count];

    memset(len, 0, sizeof(len));

    for (size_t i = 0; compact[i]; i++) {
        if (compact[i] != '.')
            len[c]++;
        else if (++c > count - 1)
            return NULL;
    }

    if (c != count - 1)
        return NULL;

    out = json_object();
    if (!out)
        return NULL;

    c = 0;
    va_start(ap, compact);
    for (size_t i = 0; i < count; i++) {
        json_t *val = json_stringn(&compact[c], len[i]);
        if (json_object_set_new(out, va_arg(ap, const char *), val) < 0) {
            json_decref(out);
            va_end(ap);
            return NULL;
        }

        c += len[i] + 1;
    }
    va_end(ap);

    if (json_object_size(out) == 0) {
        json_decref(out);
        return NULL;
    }

    return out;
}

size_t
str_to_enum(const char *str, ...)
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

bool
has_flags(const char *flags, bool all, const char *query)
{
    if (!flags || !query)
        return false;

    for (size_t i = 0; query[i]; i++) {
        const char *c = strchr(flags, query[i]);
        if (all && !c)
            return false;
        if (!all && c)
            return true;
    }

    return all;
}

json_t *
encode_protected(json_t *obj)
{
    json_t *p = NULL;

    if (json_unpack(obj, "{s?o}", "protected", &p) == -1)
        return false;

    if (!p)
        return json_string("");

    if (json_is_string(p))
        return json_incref(p);

    if (!json_is_object(p))
        return NULL;

    p = jose_b64_encode_json_dump(p, JSON_SORT_KEYS | JSON_COMPACT);
    if (!p)
        return NULL;

    if (json_object_set_new(obj, "protected", p) == -1)
        return NULL;

    return p;
}

/*
 * This really doesn't belong here, but OpenSSL doesn't (yet) help us.
 *
 * I have submitted a version of this function upstream:
 *   https://github.com/openssl/openssl/pull/1217
 */
const unsigned char *
EVP_PKEY_get0_hmac(EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_HMAC)
        return NULL;

    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}

