/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../jwk.h"
#include "../openssl.h"
#include "vect.h"
#include "jtbl.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

struct vector {
    const char *allow;
    const char *excld;
    int type;
    bool prv;
};

static const struct {
    const char *name;
    struct vector vect;
} rfc7520[] = {
    { "rfc7520_3.1", { "sig", "enc", EVP_PKEY_EC, false } },
    { "rfc7520_3.2", { "sig", "enc", EVP_PKEY_EC, true } },
    { "rfc7520_3.3", { "sig", "enc", EVP_PKEY_RSA, false } },
    { "rfc7520_3.4", { "sig", "enc", EVP_PKEY_RSA, true } },
    { "rfc7520_3.5", { "sig", "enc", EVP_PKEY_HMAC } },
    { "rfc7520_3.6", { "enc", "sig", EVP_PKEY_HMAC } },
    {}
};

static const struct {
    const char *name;
    struct vector *vect;
} rfc7517[] = {
    { "rfc7517_A.1", (struct vector[]) {
            { "enc", "sig", EVP_PKEY_EC, false },
            { NULL, NULL, EVP_PKEY_RSA, false },
            {}
        } },
    { "rfc7517_A.2", (struct vector[]) {
            { "enc", "sig", EVP_PKEY_EC, true },
            { NULL, NULL, EVP_PKEY_RSA, true },
            {}
        } },
    { "rfc7517_A.3", (struct vector[]) {
            { NULL, NULL, EVP_PKEY_HMAC, true },
            { NULL, NULL, EVP_PKEY_HMAC, true },
            {}
        } },
    {}
};

static const struct {
    const char *alg;
    const char *kty;
    const char **keys;
} generate_alg[] = {
    { "HS256", "oct", (const char *[]) { "k", NULL } },
    { "HS384", "oct", (const char *[]) { "k", NULL } },
    { "HS512", "oct", (const char *[]) { "k", NULL } },
    { "A128KW", "oct", (const char *[]) { "k", NULL } },
    { "A192KW", "oct", (const char *[]) { "k", NULL } },
    { "A256KW", "oct", (const char *[]) { "k", NULL } },
    { "A128GCMKW", "oct", (const char *[]) { "k", NULL } },
    { "A192GCMKW", "oct", (const char *[]) { "k", NULL } },
    { "A256GCMKW", "oct", (const char *[]) { "k", NULL } },
    { "A128GCM", "oct", (const char *[]) { "k", NULL } },
    { "A192GCM", "oct", (const char *[]) { "k", NULL } },
    { "A256GCM", "oct", (const char *[]) { "k", NULL } },
    { "A128CBC-HS256", "oct", (const char *[]) { "k", NULL } },
    { "A192CBC-HS384", "oct", (const char *[]) { "k", NULL } },
    { "A256CBC-HS512", "oct", (const char *[]) { "k", NULL } },

    { "RS256", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "RS384", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "RS512", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "PS256", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "PS384", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "PS512", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "RSA1_5", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "RSA-OAEP", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { "RSA-OAEP-256", "RSA", (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },

    { "ES256", "EC", (const char *[]) { "x", "y", "d", NULL } },
    { "ES384", "EC", (const char *[]) { "x", "y", "d", NULL } },
    { "ES512", "EC", (const char *[]) { "x", "y", "d", NULL } },

    {}
};

static const struct {
    jtbl_value_t val;
    const char **del;
    const char **cpy;
} generate_obj[] = {
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "oct" } },
            { "use",   { JSON_STRING,  .s = "enc" } },
            { "bytes", { JSON_INTEGER, .i = 32    } },
            {}
        } },
      .del = (const char *[]) { "bytes", NULL },
      .cpy = (const char *[]) { "k", NULL } },

    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "RSA" } },
            { "use",   { JSON_STRING,  .s = "sig" } },
            { "bits",  { JSON_INTEGER, .i = 3072  } },
            {}
        } },
      .del = (const char *[]) { "bits", NULL },
      .cpy = (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "RSA" } },
            { "use",   { JSON_STRING,  .s = "sig" } },
            { "bits",  { JSON_INTEGER, .i = 3072  } },
            { "e",     { JSON_INTEGER, .i = 257   } },
            {}
        } },
      .del = (const char *[]) { "bits", NULL },
      .cpy = (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "RSA" } },
            { "use",   { JSON_STRING,  .s = "sig" } },
            { "bits",  { JSON_INTEGER, .i = 3072  } },
            { "e",     { JSON_STRING,  .s = "AQE" } },
            {}
        } },
      .del = (const char *[]) { "bits", NULL },
      .cpy = (const char *[]) { "n", "d", "p", "q", "dp", "dq", "qi", NULL } },

    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "EC"    } },
            { "crv",   { JSON_STRING,  .s = "P-384" } },
            { "use",   { JSON_STRING,  .s = "sig"   } },
            {}
        } },
      .del = (const char *[]) { NULL },
      .cpy = (const char *[]) { "x", "y", "d", NULL } },

    {}
};

static void
test_key(const json_t *jwk, const struct vector *v)
{
    EVP_PKEY *key = NULL;
    json_t *cpy = NULL;

    json_dumpf(jwk, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n");

    if (v->allow)
        assert(jose_jwk_allowed(jwk, v->allow, NULL));
    if (v->excld)
        assert(!jose_jwk_allowed(jwk, v->excld, NULL));

    key = jose_openssl_jwk_to_key(jwk, JOSE_JWK_TYPE_ALL);
    assert(key);
    assert(EVP_PKEY_base_id(key) == v->type);

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        break;
    case EVP_PKEY_RSA:
        assert(!!key->pkey.rsa->d == v->prv);
        break;
    case EVP_PKEY_EC:
        assert(!!EC_KEY_get0_private_key(key->pkey.ec) == v->prv);
        break;
    }

    EVP_PKEY_free(key);
    cpy = json_deep_copy(jwk);
    assert(cpy);
    assert(jose_jwk_clean(cpy, JOSE_JWK_TYPE_NONE));

    key = jose_openssl_jwk_to_key(cpy, JOSE_JWK_TYPE_ALL);
    json_decref(cpy);
    assert(key);
    assert(EVP_PKEY_base_id(key) == v->type);

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        break;
    case EVP_PKEY_RSA:
        assert(!!key->pkey.rsa->d == v->prv);
        break;
    case EVP_PKEY_EC:
        assert(!!EC_KEY_get0_private_key(key->pkey.ec) == v->prv);
        break;
    }

    EVP_PKEY_free(key);
    cpy = json_deep_copy(jwk);
    assert(cpy);
    assert(jose_jwk_clean(cpy, JOSE_JWK_TYPE_ALL));

    key = jose_openssl_jwk_to_key(cpy, JOSE_JWK_TYPE_ALL);
    json_decref(cpy);

    if (v->type != EVP_PKEY_HMAC) {
        assert(key);
        assert(EVP_PKEY_base_id(key) == v->type);

        switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_HMAC:
            break;
        case EVP_PKEY_RSA:
            assert(!key->pkey.rsa->d);
            break;
        case EVP_PKEY_EC:
            assert(!EC_KEY_get0_private_key(key->pkey.ec));
            break;
        }

        EVP_PKEY_free(key);
    } else {
        assert(!key);
    }
}

static void
test_clean(void)
{
    json_t *none = NULL;
    json_t *oct = NULL;
    json_t *rsa = NULL;
    json_t *ec = NULL;
    json_t *asym = NULL;
    json_t *all = NULL;
    json_t *tmp = NULL;

    none = json_pack(
        "{s:[{s:s,s:s},{s:s,s:s},{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s}]}", "keys",
        "kty", "oct", "k", "",
        "kty", "EC", "d", "",
        "kty", "RSA", "d", "", "p", "", "q", "",
                      "dp", "", "dq", "", "qi", "", "oth", ""
    );
    oct = json_pack(
        "{s:[{s:s},{s:s,s:s},{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s}]}", "keys",
        "kty", "oct",
        "kty", "EC", "d", "",
        "kty", "RSA", "d", "", "p", "", "q", "",
                      "dp", "", "dq", "", "qi", "", "oth", ""
    );
    rsa = json_pack(
        "{s:[{s:s,s:s},{s:s,s:s},{s:s}]}", "keys",
        "kty", "oct", "k", "",
        "kty", "EC", "d", "",
        "kty", "RSA"
    );
    ec = json_pack(
        "{s:[{s:s,s:s},{s:s},{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s}]}", "keys",
        "kty", "oct", "k", "",
        "kty", "EC",
        "kty", "RSA", "d", "", "p", "", "q", "",
                      "dp", "", "dq", "", "qi", "", "oth", ""
    );
    asym = json_pack(
        "{s:[{s:s,s:s},{s:s},{s:s}]}", "keys",
        "kty", "oct", "k", "",
        "kty", "EC",
        "kty", "RSA"
    );
    all = json_pack(
        "{s:[{s:s},{s:s},{s:s}]}", "keys",
        "kty", "oct",
        "kty", "EC",
        "kty", "RSA"
    );
    assert(none);
    assert(oct);
    assert(rsa);
    assert(ec);
    assert(asym);
    assert(all);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_NONE));
    assert(json_equal(none, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_OCT));
    json_dumpf(oct, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n");
    json_dumpf(tmp, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n");
    assert(json_equal(oct, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_RSA));
    assert(json_equal(rsa, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_EC));
    assert(json_equal(ec, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_ASYM));
    assert(json_equal(asym, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_SYM));
    assert(json_equal(oct, tmp));
    json_decref(tmp);

    assert(tmp = json_deep_copy(none));
    assert(jose_jwk_clean(tmp, JOSE_JWK_TYPE_ALL));
    assert(json_equal(all, tmp));
    json_decref(tmp);

    json_decref(none);
    json_decref(oct);
    json_decref(rsa);
    json_decref(ec);
    json_decref(asym);
    json_decref(all);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; rfc7520[i].name; i++) {
        json_t *jwk = vect_json(rfc7520[i].name, "jwk");
        assert(jwk);
        test_key(jwk, &rfc7520[i].vect);
        json_decref(jwk);
    }

    for (size_t i = 0; rfc7517[i].name; i++) {
        json_t *jwkset = NULL;
        json_t *keys = NULL;

        jwkset = vect_json(rfc7517[i].name, "jwkset");
        assert(json_is_object(jwkset));

        keys = json_object_get(jwkset, "keys");
        assert(json_is_array(keys));

        for (size_t j = 0; j < json_array_size(keys); j++) {
            json_t *jwk = json_array_get(keys, j);
            test_key(jwk, &rfc7517[i].vect[j]);
        }

        json_decref(jwkset);
    }

    for (size_t i = 0; generate_alg[i].alg; i++) {
        json_t *jwk = NULL;

        fprintf(stderr, "==================== %s\n", generate_alg[i].alg);

        jwk = json_pack("{s:s}", "alg", generate_alg[i].alg);
        assert(jwk);

        assert(jose_jwk_generate(jwk));

        json_dumpf(jwk, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        assert(json_is_string(json_object_get(jwk, "kty")));
        assert(strcmp(json_string_value(json_object_get(jwk, "kty")),
                      generate_alg[i].kty) == 0);

        for (size_t j = 0; generate_alg[i].keys[j]; j++)
            assert(json_object_get(jwk, generate_alg[i].keys[j]));

        assert(json_is_string(json_object_get(jwk, "use")));
        assert(json_is_array(json_object_get(jwk, "key_ops")));
        json_decref(jwk);
    }

    for (size_t i = 0; generate_obj[i].cpy; i++) {
        json_t *jwk = NULL;
        json_t *key = NULL;

        jwk = jtbl_make(&generate_obj[i].val);
        assert(jwk);

        json_dumpf(jwk, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        assert(jose_jwk_generate(jwk));

        json_dumpf(jwk, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        key = jtbl_make(&generate_obj[i].val);
        assert(key);

        json_dumpf(key, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        for (size_t j = 0; generate_obj[i].del[j]; j++)
            assert(json_object_del(key, generate_obj[i].del[j]) == 0);

        for (size_t j = 0; generate_obj[i].cpy[j]; j++) {
            json_t *tmp = json_object_get(jwk, generate_obj[i].cpy[j]);
            assert(tmp);
            assert(json_object_set(key, generate_obj[i].cpy[j], tmp) == 0);
        }

        json_dumpf(key, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        assert(json_equal(jwk, key));

        json_decref(jwk);
        json_decref(key);
    }

    test_clean();
    return 0;
}
