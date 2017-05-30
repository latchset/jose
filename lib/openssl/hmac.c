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

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "HS256", "HS384", "HS512"

typedef struct {
    jose_io_t io;

    HMAC_CTX *hctx;
    json_t *obj;
    json_t *sig;
} io_t;

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    HMAC_CTX_free(i->hctx);
    json_decref(i->obj);
    json_decref(i->sig);
    free(i);
}

static bool
io_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    return HMAC_Update(i->hctx, in, len) > 0;
}

static bool
sig_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t hash[HMAC_size(i->hctx)];
    unsigned int len = 0;

    if (HMAC_Final(i->hctx, hash, &len) <= 0 || len != sizeof(hash))
        return false;

    if (json_object_set_new(i->sig, "signature",
                            jose_b64_enc(hash, sizeof(hash))) < 0)
        return false;

    return add_entity(i->obj, i->sig,
                      "signatures", "signature", "protected", "header", NULL);
}

static bool
ver_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t hash[HMAC_size(i->hctx)];
    uint8_t test[HMAC_size(i->hctx)];
    const json_t *sig = NULL;
    unsigned int len = 0;

    sig = json_object_get(i->sig, "signature");
    if (!sig)
        return false;

    if (jose_b64_dec(sig, NULL, 0) != sizeof(test))
        return false;

    if (jose_b64_dec(sig, test, sizeof(test)) != sizeof(test))
        return false;

    if (HMAC_Final(i->hctx, hash, &len) <= 0 || len != sizeof(hash))
        return false;

    return CRYPTO_memcmp(hash, test, sizeof(hash)) == 0;
}

static HMAC_CTX *
hmac(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
     const json_t *sig, const json_t *jwk)
{
    uint8_t key[KEYMAX] = {};
    const EVP_MD *md = NULL;
    const char *prot = NULL;
    HMAC_CTX *hctx = NULL;
    size_t keyl = 0;

    if (json_unpack((json_t *) sig, "{s?s}", "protected", &prot) < 0)
        return NULL;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    keyl = jose_b64_dec(json_object_get(jwk, "k"), NULL, 0);
    if (keyl == SIZE_MAX) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Error decoding JWK");
        return NULL;
    }

    /* Per RFC 7518 Section 3.2 */
    if (keyl < (size_t) EVP_MD_size(md)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "Key is too small (cf. RFC 7518 Section 3.2)");
        return NULL;
    }

    if (keyl > KEYMAX) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Key is too large");
        return NULL;
    }

    if (jose_b64_dec(json_object_get(jwk, "k"), key, sizeof(key)) != keyl) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID,
                     "JWK 'k' parameter contains invalid Base64");
        goto error;
    }

    hctx = HMAC_CTX_new();
    if (!hctx)
        goto error;

    if (HMAC_Init_ex(hctx, key, keyl, md, NULL) <= 0)
        goto error;

    if (prot && HMAC_Update(hctx, (uint8_t *) prot, strlen(prot)) <= 0)
        goto error;

    if (HMAC_Update(hctx, (uint8_t *) ".", 1) <= 0)
        goto error;

    OPENSSL_cleanse(key, sizeof(key));
    return hctx;

error:
    OPENSSL_cleanse(key, sizeof(key));
    HMAC_CTX_free(hctx);
    return NULL;
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
    json_int_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) < 0)
        return NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return NULL;
    }

    return json_pack("{s:{s:s,s:I}}", "upd", "kty", "oct", "bytes", len);
}

static const char *
alg_sign_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *name = NULL;
    const char *type = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s?s,s?s}", "alg", &name, "kty", &type) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "oct") != 0)
        return NULL;

    len = jose_b64_dec(json_object_get(jwk, "k"), NULL, 0);
    if (len == SIZE_MAX)
        return NULL;

    if (len >= SHA512_DIGEST_LENGTH)
        return "HS512";
    else if (len >= SHA384_DIGEST_LENGTH)
        return "HS384";
    else if (len >= SHA256_DIGEST_LENGTH)
        return "HS256";

    return NULL;
}

static jose_io_t *
alg_sign_sig(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jws,
             json_t *sig, const json_t *jwk)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return false;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = sig_done;
    io->free = io_free;

    i->obj = json_incref(jws);
    i->sig = json_incref(sig);
    i->hctx = hmac(alg, cfg, sig, jwk);
    if (!i->obj || !i->sig || !i->hctx)
        return NULL;

    return jose_io_incref(io);
}

static jose_io_t *
alg_sign_ver(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jws,
             const json_t *sig, const json_t *jwk)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return false;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = ver_done;
    io->free = io_free;

    i->sig = json_incref((json_t *) sig);
    i->hctx = hmac(alg, cfg, sig, jwk);
    if (!i->sig || !i->hctx)
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
          .name = "HS256",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "HS384",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "HS512",
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
