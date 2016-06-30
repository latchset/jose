/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"
#include "b64.h"
#include "core.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static jose_jwk_resolver_t *resolvers;
static jose_jwk_generator_t *generators;

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver)
{
    resolver->next = resolvers;
    resolvers = resolver;
}

void
jose_jwk_register_generator(jose_jwk_generator_t *generator)
{
    generator->next = generators;
    generators = generator;
}

jose_jwk_type_t
jose_jwk_type(const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return JOSE_JWK_TYPE_NONE;

    switch (core_str2enum(kty, "oct", "RSA", "EC", NULL)) {
    case 0: return JOSE_JWK_TYPE_OCT;
    case 1: return JOSE_JWK_TYPE_RSA;
    case 2: return JOSE_JWK_TYPE_EC;
    default: return JOSE_JWK_TYPE_NONE;
    }
}

bool
jose_jwk_generate(json_t *jwk)
{
    const char *kty = NULL;

    for (jose_jwk_resolver_t *r = resolvers; r; r = r->next) {
        if (!r->resolve(jwk))
            return false;
    }

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (jose_jwk_generator_t *g = generators; g; g = g->next) {
        if (strcmp(g->kty, kty) == 0)
            return g->generate(jwk);
    }

    return false;
}

static bool
jwk_clean(json_t *jwk, jose_jwk_type_t types)
{
    static const struct {
        jose_jwk_type_t type;
        const char *key;
    } table[] = {
        { JOSE_JWK_TYPE_OCT, "k" },

        { JOSE_JWK_TYPE_RSA, "p" },
        { JOSE_JWK_TYPE_RSA, "d" },
        { JOSE_JWK_TYPE_RSA, "q" },
        { JOSE_JWK_TYPE_RSA, "dp" },
        { JOSE_JWK_TYPE_RSA, "dq" },
        { JOSE_JWK_TYPE_RSA, "qi" },
        { JOSE_JWK_TYPE_RSA, "oth" },

        { JOSE_JWK_TYPE_EC, "d" },

        {}
    };

    const jose_jwk_type_t type = jose_jwk_type(jwk);

    for (size_t i = 0; table[i].key; i++) {
        if ((table[i].type & types & type) == 0)
            continue;

        if (!json_object_get(jwk, table[i].key))
            continue;

        if (json_object_del(jwk, table[i].key) == -1)
            return false;
    }

    return true;
}

bool
jose_jwk_clean(json_t *jwk, jose_jwk_type_t types)
{
    json_t *keys = NULL;

    if (json_is_array(jwk))
        keys = jwk;
    else if (json_is_array(json_object_get(jwk, "keys")))
        keys = json_object_get(jwk, "keys");

    if (!keys)
        return jwk_clean(jwk, types);

    for (size_t i = 0; i < json_array_size(keys); i++) {
        if (!jwk_clean(json_array_get(keys, i), types))
            return false;
    }

    return true;
}

static bool
uallowed(const json_t *jwk, const char *use)
{
    json_t *u = NULL;

    u = json_object_get(jwk, "use");
    if (!json_is_string(u))
        return true;

    return strcmp(json_string_value(u), use) == 0;
}

static bool
oallowed(const json_t *jwk, const char *op)
{
    json_t *ko = NULL;

    ko = json_object_get(jwk, "key_ops");
    if (!json_is_array(ko))
        return true;

    for (size_t i = 0; i < json_array_size(ko); i++) {
        json_t *o = NULL;

        o = json_array_get(ko, i);
        if (!json_is_string(o))
            continue;

        if (strcmp(json_string_value(o), op) == 0)
            return true;
    }

    return false;
}

bool
jose_jwk_allowed(const json_t *jwk, const char *use, const char *op)
{
    if (!use) {
        switch (core_str2enum(op, "sign", "verify", "encrypt", "decrypt",
                              "wrapKey", "unwrapKey", "deriveKey",
                              "deriveBits", NULL)) {
        case 0: use = "sig"; break;
        case 1: use = "sig"; break;
        case 2: use = "enc"; break;
        case 3: use = "enc"; break;
        case 4: use = "enc"; break;
        case 5: use = "enc"; break;
        default: break;
        }
    }

    return use ? uallowed(jwk, use) : true && op ? oallowed(jwk, op) : true;
}
