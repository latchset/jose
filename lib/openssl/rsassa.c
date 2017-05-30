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

#include <openssl/sha.h>

#include <string.h>

#define NAMES "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"

typedef typeof(EVP_DigestSignInit) init_t;

declare_cleanup(EVP_PKEY)

typedef struct {
    jose_io_t io;

    EVP_MD_CTX *emc;
    json_t *obj;
    json_t *sig;
} io_t;

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    EVP_MD_CTX_free(i->emc);
    json_decref(i->obj);
    json_decref(i->sig);
    free(i);
}

static bool
io_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    return EVP_DigestUpdate(i->emc, in, len) > 0;
}

static bool
sig_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    size_t len = 0;

    if (EVP_DigestSignFinal(i->emc, NULL, &len) <= 0)
        return false;

    uint8_t buf[len];

    if (EVP_DigestSignFinal(i->emc, buf, &len) <= 0)
        return false;

    if (json_object_set_new(i->sig, "signature",
                            jose_b64_enc(buf, len)) < 0)
        return false;

    return add_entity(i->obj, i->sig,
                      "signatures", "signature", "protected", "header", NULL);
}

static bool
ver_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    const json_t *sig = NULL;
    uint8_t *buf = NULL;
    bool ret = false;
    size_t len = 0;

    sig = json_object_get(i->sig, "signature");
    if (!sig)
        return false;

    len = jose_b64_dec(sig, NULL, 0);
    if (len == SIZE_MAX)
        return false;

    buf = malloc(len);
    if (!buf)
        return false;

    if (jose_b64_dec(sig, buf, len) != len) {
        free(buf);
        return false;
    }

    ret = EVP_DigestVerifyFinal(i->emc, buf, len) == 1;
    free(buf);
    return ret;
}

static EVP_MD_CTX *
setup(jose_cfg_t *cfg, const json_t *jwk, const json_t *sig, const char *alg,
      init_t *func)
{
    openssl_auto(EVP_PKEY) *key = NULL;
    EVP_PKEY_CTX *epc = NULL;
    const EVP_MD *md = NULL;
    const char *prot = NULL;
    EVP_MD_CTX *emc = NULL;
    const RSA *rsa = NULL;
    int slen = 0;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    default: return NULL;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(cfg, jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Don't use small keys. RFC 7518 3.3 */
    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return NULL;
    if (RSA_size(rsa) < 2048 / 8)
        return NULL;

    emc = EVP_MD_CTX_new();
    if (!emc)
        return NULL;

    if (func(emc, &epc, md, NULL, key) <= 0)
        goto error;

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0)
        goto error;

    if (slen != 0) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(epc, slen) <= 0)
            goto error;
    }

    if (json_unpack((json_t *) sig, "{s?s}", "protected", &prot) < 0)
        goto error;

    if (prot && EVP_DigestUpdate(emc, prot, strlen(prot)) <= 0)
        goto error;

    if (EVP_DigestUpdate(emc, ".", 1) <= 0)
        goto error;

    return emc;

error:
    EVP_MD_CTX_free(emc);
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
    if (!jwk_prep_handles(cfg, jwk))
        return NULL;

    return json_pack("{s:{s:s}}", "upd", "kty", "RSA");
}

static const char *
alg_sign_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *name = NULL;
    const char *type = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s?s,s?s}",
                    "alg", &name, "kty", &type) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "RSA") != 0)
        return NULL;

    len = jose_b64_dec(json_object_get(jwk, "n"), NULL, 0) * 8;

    switch ((len < 4096 ? len : 4096) & (4096 | 3072 | 2048)) {
    case 4096: return "RS512";
    case 3072: return "RS384";
    case 2048: return "RS256";
    default: return NULL;
    }
}

static jose_io_t *
alg_sign_sig(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jws,
             json_t *sig, const json_t *jwk)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = sig_done;
    io->free = io_free;

    i->obj = json_incref(jws);
    i->sig = json_incref(sig);
    i->emc = setup(cfg, jwk, sig, alg->name, EVP_DigestSignInit);
    if (!i->obj || !i->sig || !i->emc)
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
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = io_feed;
    io->done = ver_done;
    io->free = io_free;

    i->sig = json_incref((json_t *) sig);
    i->emc = setup(cfg, jwk, sig, alg->name, EVP_DigestVerifyInit);
    if (!i->sig || !i->emc)
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
          .name = "RS256",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "RS384",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "RS512",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "PS256",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "PS384",
          .sign.sprm = "sign",
          .sign.vprm = "verify",
          .sign.sug = alg_sign_sug,
          .sign.sig = alg_sign_sig,
          .sign.ver = alg_sign_ver },
        { .kind = JOSE_HOOK_ALG_KIND_SIGN,
          .name = "PS512",
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
