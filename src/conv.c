/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "conv.h"
#include "lbuf.h"
#include "b64.h"

#include <openssl/evp.h>
#include <string.h>

BIGNUM *
bn_from_buf(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_from_json(const json_t *json)
{
    lbuf_t *lbuf = NULL;
    BIGNUM *bn = NULL;

    lbuf = lbuf_new(jose_b64_dlen(json_string_length(json)));
    if (!lbuf)
        return NULL;

    if (jose_b64_decode_json(json, lbuf->buf))
        bn = bn_from_buf(lbuf->buf, lbuf->len);

    lbuf_free(lbuf);
    return bn;
}

bool
bn_to_buf(const BIGNUM *bn, uint8_t buf[], size_t len)
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
bn_to_json(const BIGNUM *bn, size_t len)
{
    json_t *out = NULL;
    lbuf_t *lbuf = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    lbuf = lbuf_new(len);
    if (!lbuf)
        return NULL;

    if (bn_to_buf(bn, lbuf->buf, len))
        out = jose_b64_encode_json(lbuf->buf, lbuf->len);

    lbuf_free(lbuf);
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
string_to_enum(const char *str, bool icase, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, icase);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && !icase && strcmp(str, v) == 0)
            break;
        if (str && icase && strcasecmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
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

