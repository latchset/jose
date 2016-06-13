/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "bn.h"
#include "b64.h"

#include <string.h>

BIGNUM *
bn_from_buf(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_from_json(const json_t *json)
{
    jose_key_t *key = NULL;
    BIGNUM *bn = NULL;

    key = jose_b64_decode_key(json);
    if (key)
        bn = bn_from_buf(key->key, key->len);

    jose_key_free(key);
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
    jose_key_t *key = NULL;
    json_t *out = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    key = jose_key_new(len);
    if (!key)
        return NULL;

    if (bn_to_buf(bn, key->key, len))
        out = jose_b64_encode_key(key);

    jose_key_free(key);
    return out;
}
