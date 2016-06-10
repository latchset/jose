/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "json.h"
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

jose_key_t *
json_to_key(const json_t *json)
{
    jose_key_t *key = NULL;
    BIO *mem = NULL;
    BIO *b64 = NULL;
    int len = 0;

    if (!json_is_string(json))
        return NULL;

    key = jose_key_new((json_string_length(json) + 3) / 4 * 3);
    if (!key)
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
        goto error;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new_mem_buf(json_string_value(json), json_string_length(json));
    if (!mem)
        goto error;

    b64 = BIO_push(b64, mem);

    len = BIO_read(b64, key->key, key->len);
    if (len < 0)
        goto error;

    BIO_free_all(b64);
    key->len = len;
    return key;

error:
    BIO_free_all(b64);
    jose_key_free(key);
    return NULL;
}

json_t *
json_from_key(const jose_key_t *key)
{
    json_t *json = NULL;
    char *buf = NULL;
    BIO *mem = NULL;
    BIO *b64 = NULL;
    long len = 0;

    if (!key)
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
        goto error;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new(BIO_s_mem());
    if (!mem)
        goto error;

    b64 = BIO_push(b64, mem);

    if (BIO_write(b64, key->key, key->len) != (int) key->len)
        goto error;

    BIO_flush(b64);

    len = BIO_get_mem_data(mem, &buf);
    if (len < (int) key->len / 3 * 4)
        goto error;

    if (len == 0)
        json = json_string("");
    else
        json = json_stringn(buf, len);

error:
    BIO_free_all(b64);
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

