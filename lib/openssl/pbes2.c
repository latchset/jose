/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <openssl/rand.h>

#include <string.h>

#define NAMES "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"

extern jose_jwe_wrapper_t aeskw_wrapper;

static const char *
suggest(const json_t *jwk)
{
    if (!json_is_string(jwk))
        return NULL;

    return "PBES2-HS256+A128KW";
}

static json_t *
pbkdf2(const json_t *jwk, const char *alg, int iter, uint8_t st[], size_t stl)
{
    const EVP_MD *md = NULL;
    uint8_t *salt = NULL;
    json_t *key = NULL;
    json_t *p = NULL;
    size_t saltl = 0;
    size_t dkl = 0;

    if (!json_is_string(jwk))
        return NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); dkl = 16; break;
    case 1: md = EVP_sha384(); dkl = 24; break;
    case 2: md = EVP_sha512(); dkl = 32; break;
    default: return NULL;
    }

    uint8_t dk[dkl];

    saltl = strlen(alg) + 1 + stl;
    salt = malloc(saltl);
    if (!salt)
        goto egress;

    memcpy(salt, alg, saltl - stl);
    memcpy(&salt[saltl - stl], st, stl);

    if (PKCS5_PBKDF2_HMAC(json_string_value(jwk), json_string_length(jwk),
                          salt, saltl, iter, md, dkl, dk) > 0) {
        key = json_pack("{s:s,s:o}", "kty", "oct", "k",
                        jose_b64_encode_json(dk, sizeof(dk)));
    }

egress:
    memset(dk, 0, sizeof(dk));
    clear_free(salt, saltl);
    json_decref(p);
    return key;
}

static bool
wrap(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
{
    const char *aes = NULL;
    json_t *p2c = NULL;
    json_t *key = NULL;
    json_t *jh = NULL;
    json_t *h = NULL;
    bool ret = false;
    size_t stl = 0;
    int iter;

    if (!json_object_get(cek, "k") && !jose_jwk_generate(cek))
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: aes = "A128KW"; stl = 16; break;
    case 1: aes = "A192KW"; stl = 24; break;
    case 2: aes = "A256KW"; stl = 32; break;
    default: return false;
    }

    uint8_t st[stl];

    if (RAND_bytes(st, stl) <= 0)
        goto egress;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        goto egress;

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        goto egress;

    p2c = json_object_get(jh, "p2c");
    if (p2c) {
        if (!json_is_integer(p2c))
            goto egress;

        iter = json_integer_value(p2c);
        if (iter < 1000)
            goto egress;
    } else {
        iter = 10000;
        if (json_object_set_new(h, "p2c", json_integer(iter)) == -1)
            goto egress;
    }

    if (json_object_set_new(h, "p2s", jose_b64_encode_json(st, stl)) == -1)
        goto egress;

    key = pbkdf2(jwk, alg, iter, st, stl);
    if (key)
        ret = aeskw_wrapper.wrap(jwe, cek, key, rcp, aes);
    json_decref(key);

egress:
    json_decref(jh);
    return ret;
}

static bool
unwrap(const json_t *jwe, const json_t *jwk, const json_t *rcp,
       const char *alg, json_t *cek)
{
    const char *aes = NULL;
    const char *p2s = NULL;
    json_int_t p2c = -1;
    uint8_t *st = NULL;
    json_t *key = NULL;
    json_t *jh = NULL;
    bool ret = false;
    size_t stl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: aes = "A128KW"; break;
    case 1: aes = "A192KW"; break;
    case 2: aes = "A256KW"; break;
    default: return false;
    }

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        goto egress;

    if (json_unpack(jh, "{s:s,s:I}", "p2s", &p2s, "p2c", &p2c) == -1)
        goto egress;

    st = jose_b64_decode(p2s, &stl);
    if (!st || stl < 8)
        goto egress;

    key = pbkdf2(jwk, alg, p2c, st, stl);
    if (key)
        ret = aeskw_wrapper.unwrap(jwe, key, rcp, aes, cek);
    json_decref(key);

egress:
    json_decref(jh);
    free(st);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *algs[] = { NAMES, NULL };

    static jose_jwe_wrapper_t wrapper = {
        .algs = algs,
        .suggest = suggest,
        .wrap = wrap,
        .unwrap = unwrap,
    };

    jose_jwe_register_wrapper(&wrapper);
}
