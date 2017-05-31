/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc.h"
#include <jose/b64.h>
#include "../hooks.h"
#include <jose/openssl.h>

#include <string.h>

#define NAMES "ES256", "ES384", "ES512"

typedef struct {
    jose_io_t io;

    jose_io_t *h;
    jose_io_t *b;
    EC_KEY *key;
    json_t *obj;
    json_t *sig;

    size_t hshl;
    void *hsh;
} io_t;

declare_cleanup(ECDSA_SIG)

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    if (i->h)
        i->h->free(i->h);
    if (i->b)
        i->b->free(i->b);
    EC_KEY_free(i->key);
    json_decref(i->obj);
    json_decref(i->sig);
    free(i);
}

static bool
io_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    return i->h->feed(i->h, in, len);
}

static bool
sig_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t buf[(EC_GROUP_get_degree(EC_KEY_get0_group(i->key)) + 7) / 8 * 2];
    openssl_auto(ECDSA_SIG) *ecdsa = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    if (!i->h->done(i->h))
        return false;

    ecdsa = ECDSA_do_sign(i->hsh, i->hshl, i->key);
    if (!ecdsa)
        return false;

    ECDSA_SIG_get0(ecdsa, &r, &s);

    if (!bn_encode(r, buf, sizeof(buf) / 2))
        return false;

    if (!bn_encode(s, &buf[sizeof(buf) / 2], sizeof(buf) / 2))
        return false;

    if (json_object_set_new(i->sig, "signature",
                            jose_b64_enc(buf, sizeof(buf))) < 0)
        return false;

    return add_entity(i->obj, i->sig,
                      "signatures", "signature", "protected", "header", NULL);
}

static bool
ver_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t buf[(EC_GROUP_get_degree(EC_KEY_get0_group(i->key)) + 7) / 8 * 2];
    openssl_auto(ECDSA_SIG) *ecdsa = NULL;
    const json_t *sig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;

    sig = json_object_get(i->sig, "signature");
    if (!sig)
        return false;

    if (jose_b64_dec(sig, NULL, 0) != sizeof(buf))
        return false;

    if (jose_b64_dec(sig, buf, sizeof(buf)) != sizeof(buf))
        return false;

    ecdsa = ECDSA_SIG_new();
    if (!ecdsa)
        return false;

    r = bn_decode(buf, sizeof(buf) / 2);
    s = bn_decode(&buf[sizeof(buf) / 2], sizeof(buf) / 2);
    if (ECDSA_SIG_set0(ecdsa, r, s) <= 0) {
        BN_free(r);
        BN_free(s);
        return false;
    }

    if (!i->h->done(i->h))
        return false;

    return ECDSA_do_verify(i->hsh, i->hshl, ecdsa, i->key) == 1;
}

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

static json_t *
jwk_prep_execute(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;
    const char *grp = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: grp = "P-256"; break;
    case 1: grp = "P-384"; break;
    case 2: grp = "P-521"; break;
    default: return false;
    }

    return json_pack("{s:{s:s,s:s}}", "upd", "kty", "EC", "crv", grp);
}

static const char *
alg_sign_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *name = NULL;
    const char *type = NULL;
    const char *curv = NULL;

    if (json_unpack((json_t *) jwk, "{s?s,s?s,s?s}",
                    "alg", &name, "kty", &type, "crv", &curv) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "EC") != 0)
        return NULL;

    switch (str2enum(curv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "ES256";
    case 1: return "ES384";
    case 2: return "ES512";
    default: return NULL;
    }
}

static jose_io_t *
alg_sign_sig(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jws,
             json_t *sig, const json_t *jwk)
{
    const jose_hook_alg_t *halg = NULL;
    jose_io_auto_t *io = NULL;
    const char *prot = NULL;
    io_t *i = NULL;
    size_t plen = 0;

    if (json_unpack(sig, "{s?s%}", "protected", &prot, &plen) < 0)
        return NULL;

    halg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, &alg->name[1]);
    if (!halg)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = sig_done;
    io->free = io_free;

    i->b = jose_io_malloc(cfg, &i->hsh, &i->hshl);
    i->h = halg->hash.hsh(halg, cfg, i->b);
    i->obj = json_incref(jws);
    i->sig = json_incref(sig);
    i->key = jose_openssl_jwk_to_EC_KEY(cfg, jwk);
    if (!i->b || !i->h || !i->obj || !i->sig || !i->key)
        return NULL;

    if (prot && !i->h->feed(i->h, prot, plen))
        return NULL;

    if (!i->h->feed(i->h, ".", 1))
        return NULL;

    return jose_io_incref(io);
}

static jose_io_t *
alg_sign_ver(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jws,
             const json_t *sig, const json_t *jwk)
{
    const jose_hook_alg_t *halg = NULL;
    jose_io_auto_t *io = NULL;
    const char *prot = NULL;
    io_t *i = NULL;
    size_t plen = 0;

    if (json_unpack((json_t *) sig, "{s?s%}", "protected", &prot, &plen) < 0)
        return NULL;

    halg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, &alg->name[1]);
    if (!halg)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = ver_done;
    io->free = io_free;

    i->b = jose_io_malloc(cfg, &i->hsh, &i->hshl);
    i->h = halg->hash.hsh(halg, cfg, i->b);
    i->sig = json_incref((json_t *) sig);
    i->key = jose_openssl_jwk_to_EC_KEY(cfg, jwk);
    if (!i->b || !i->h || !i->sig || !i->key)
        return NULL;

    if (prot && !i->h->feed(i->h, prot, plen))
        return NULL;

    if (!i->h->feed(i->h, ".", 1))
        return NULL;

    return jose_io_incref(io);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_PREP,
        .prep.handles = jwk_prep_handles,
        .prep.execute = jwk_prep_execute,
    };

    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "ES256",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "ES384",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "ES512",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        {}
    };

    jose_hook_jwk_push(&jwk);
    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}
