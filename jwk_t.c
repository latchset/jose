/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/objects.h>

static const struct vector {
    const char *crv;
    int nid;
    const char *x;
    const char *y;
    const char *d;
} vectors[] = {
    { "P-256", NID_X9_62_prime256v1,
        "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE" },
    {}
};

static void
has_value(const json_t *obj, const char *name, const char *value)
{
    const json_t *tmp = NULL;

    assert(json_is_object(obj));

    tmp = json_object_get(obj, name);
    assert(json_is_string(tmp));

    assert(strcmp(json_string_value(tmp), value) == 0);
}

static void
test(json_t *jwk, const struct vector *v, bool valid, bool prv, BN_CTX *ctx)
{
    EC_KEY *key = NULL;

    key = jose_jwk_to_ec(jwk, ctx);
    if (!valid) {
        assert(!key);
        return;
    }

    assert(key);
    assert(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)) == v->nid);
    assert(EC_POINT_cmp(EC_KEY_get0_group(key),
                        EC_KEY_get0_public_key(key),
                        EC_GROUP_get0_generator(EC_KEY_get0_group(key)),
                        ctx) == 0);

    if (prv) {
        assert(EC_KEY_get0_private_key(key) != NULL);
        assert(BN_is_word(EC_KEY_get0_private_key(key), 1));
    } else {
        assert(EC_KEY_get0_private_key(key) == NULL);
    }

    jwk = jose_jwk_from_ec(key, ctx);

    has_value(jwk, "kty", "EC");
    has_value(jwk, "crv", v->crv);
    has_value(jwk, "x", v->x);
    has_value(jwk, "y", v->y);

    if (prv)
        has_value(jwk, "d", v->d);

    EC_KEY_free(key);
    json_decref(jwk);
}

int
main(int argc, char *argv[])
{
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    assert(ctx);

    for (size_t i = 0; vectors[i].crv; i++) {
        json_t *jwk = NULL;


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "x", vectors[i].x,
                        "y", vectors[i].y,
                        "d", vectors[i].d);
        assert(jwk);

        test(jwk, &vectors[i], true, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "d", vectors[i].d);
        assert(jwk);
        test(jwk, &vectors[i], true, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "x", vectors[i].x,
                        "y", vectors[i].y);
        assert(jwk);
        test(jwk, &vectors[i], true, false, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "XXX",
                        "crv", vectors[i].crv,
                        "x", vectors[i].x,
                        "y", vectors[i].y,
                        "d", vectors[i].d);
        assert(jwk);

        test(jwk, &vectors[i], false, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", "XXX",
                        "x", vectors[i].x,
                        "y", vectors[i].y,
                        "d", vectors[i].d);
        assert(jwk);

        test(jwk, &vectors[i], false, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "x", "XXX",
                        "y", vectors[i].y,
                        "d", vectors[i].d);
        assert(jwk);

        test(jwk, &vectors[i], false, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "x", vectors[i].x,
                        "y", "XXX",
                        "d", vectors[i].d);
        assert(jwk);

        test(jwk, &vectors[i], false, true, ctx);
        json_decref(jwk);


        jwk = json_pack("{s:s, s:s, s:s, s:s, s:s}",
                        "kty", "EC",
                        "crv", vectors[i].crv,
                        "x", vectors[i].x,
                        "y", vectors[i].y,
                        "d", "XXX");
        assert(jwk);

        test(jwk, &vectors[i], false, true, ctx);
        json_decref(jwk);
    }

    BN_CTX_free(ctx);
    return 0;
}
