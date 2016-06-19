/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"
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
    jtbl_value_t val;
    const char **del;
    const char **cpy;
} new_keys[] = {
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "oct" } },
            { "use",   { JSON_STRING,  .s = "sig" } },
            {}
        } },
      .del = (const char *[]) { NULL },
      .cpy = (const char *[]) { "k", NULL } },
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
            {}
        } },
      .del = (const char *[]) { NULL },
      .cpy = (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "RSA" } },
            { "use",   { JSON_STRING,  .s = "enc" } },
            { "e",     { JSON_INTEGER, .i = 257   } },
            {}
        } },
      .del = (const char *[]) { NULL },
      .cpy = (const char *[]) { "n", "e", "d", "p", "q", "dp", "dq", "qi", NULL } },
    { .val = { JSON_OBJECT, .o = (jtbl_named_t[]) {
            { "kty",   { JSON_STRING,  .s = "RSA" } },
            { "use",   { JSON_STRING,  .s = "enc" } },
            { "e",     { JSON_STRING,  .s = "AQE" } },
            {}
        } },
      .del = (const char *[]) { NULL },
      .cpy = (const char *[]) { "n", "d", "p", "q", "dp", "dq", "qi", NULL } },
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
        assert(jose_jwk_use_allowed(jwk, v->allow));
    if (v->excld)
        assert(!jose_jwk_use_allowed(jwk, v->excld));

    key = jose_jwk_to_key(jwk);
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
    cpy = jose_jwk_copy(jwk, true);
    assert(cpy);

    key = jose_jwk_to_key(cpy);
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
    cpy = jose_jwk_copy(jwk, false);
    assert(cpy);

    key = jose_jwk_to_key(cpy);
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

    for (size_t i = 0; new_keys[i].cpy; i++) {
        json_t *jwk = NULL;
        json_t *key = NULL;

        jwk = jtbl_make(&new_keys[i].val);
        assert(jwk);
        assert(jose_jwk_generate(jwk));

        json_dumpf(jwk, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        key = jtbl_make(&new_keys[i].val);
        assert(key);

        json_dumpf(key, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        for (size_t j = 0; new_keys[i].del[j]; j++)
            assert(json_object_del(key, new_keys[i].del[j]) == 0);

        for (size_t j = 0; new_keys[i].cpy[j]; j++) {
            json_t *tmp = json_object_get(jwk, new_keys[i].cpy[j]);
            assert(tmp);
            assert(json_object_set(key, new_keys[i].cpy[j], tmp) == 0);
        }

        json_dumpf(key, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n");

        assert(json_equal(jwk, key));

        json_decref(jwk);
        json_decref(key);
    }

    return 0;
}
