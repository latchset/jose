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

#include <string.h>

#define NAMES "A128GCM", "A192GCM", "A256GCM"

typedef struct {
    jose_io_t io;

    EVP_CIPHER_CTX *cctx;
    jose_io_t *next;
    json_t *json;
} io_t;

static EVP_CIPHER_CTX *
setup(const EVP_CIPHER *cph, jose_cfg_t *cfg, const json_t *jwe,
      const json_t *cek, const uint8_t iv[],
      typeof(EVP_EncryptInit_ex) *init, typeof(EVP_EncryptUpdate) *push)
{
    uint8_t key[EVP_CIPHER_key_length(cph)];
    EVP_CIPHER_CTX *ecc = NULL;
    const char *aad = NULL;
    const char *prt = NULL;
    size_t aadl = 0;
    size_t prtl = 0;
    int tmp;

    if (json_unpack((json_t *) jwe, "{s?s%,s?s%}",
                    "aad", &aad, &aadl, "protected", &prt, &prtl) < 0)
        goto error;

    ecc = EVP_CIPHER_CTX_new();
    if (!ecc)
        return NULL;

    if (init(ecc, cph, NULL, NULL, NULL) <= 0)
        goto error;

    if (jose_b64_dec(json_object_get(cek, "k"), NULL, 0) != sizeof(key))
        goto error;

    if (jose_b64_dec(json_object_get(cek, "k"), key,
                     sizeof(key)) != sizeof(key)) {
        OPENSSL_cleanse(key, sizeof(key));
        goto error;
    }

    tmp = init(ecc, NULL, NULL, key, iv);
    OPENSSL_cleanse(key, sizeof(key));
    if (tmp <= 0)
        goto error;

    if (prt && push(ecc, NULL, &tmp, (uint8_t *) prt, prtl) <= 0)
        goto error;

    if (aad) {
        if (push(ecc, NULL, &tmp, (uint8_t *) ".", 1) <= 0)
            goto error;

        if (push(ecc, NULL, &tmp, (uint8_t *) aad, prtl) <= 0)
            goto error;
    }

    return ecc;

error:
    EVP_CIPHER_CTX_free(ecc);
    return NULL;
}

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    EVP_CIPHER_CTX_free(i->cctx);
    jose_io_decref(i->next);
    json_decref(i->json);
    free(i);
}

static bool
enc_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    const uint8_t *pt = in;
    int l = 0;

    for (size_t j = 0; j < len; j++) {
        uint8_t ct[EVP_CIPHER_CTX_block_size(i->cctx) + 1];

        if (EVP_EncryptUpdate(i->cctx, ct, &l, &pt[j], 1) <= 0)
            return false;

        if (!i->next->feed(i->next, ct, l))
            return false;
    }

    return true;
}

static bool
enc_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t ct[EVP_CIPHER_CTX_block_size(i->cctx) + 1];
    uint8_t tg[EVP_GCM_TLS_TAG_LEN] = {};
    int l = 0;

    if (EVP_EncryptFinal(i->cctx, ct, &l) <= 0)
        return false;

    if (!i->next->feed(i->next, ct, l) || !i->next->done(i->next))
        return false;

    if (EVP_CIPHER_CTX_ctrl(i->cctx, EVP_CTRL_GCM_GET_TAG, sizeof(tg), tg) <= 0)
        return false;

    if (json_object_set_new(i->json, "tag",
                            jose_b64_enc(tg, sizeof(tg))) < 0)
        return false;

    return true;
}

static bool
dec_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t pt[EVP_CIPHER_CTX_block_size(i->cctx) + 1];
    const uint8_t *ct = in;
    bool ret = false;
    int l = 0;

    for (size_t j = 0; j < len; j++) {
        if (EVP_DecryptUpdate(i->cctx, pt, &l, &ct[j], 1) <= 0)
            goto egress;

        if (i->next->feed(i->next, pt, l) != (size_t) l)
            goto egress;
    }

    ret = true;

egress:
    OPENSSL_cleanse(pt, sizeof(pt));
    return ret;
}

static bool
dec_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t pt[EVP_CIPHER_CTX_block_size(i->cctx) + 1];
    uint8_t tg[EVP_GCM_TLS_TAG_LEN] = {};
    json_t *tag = NULL;
    int l = 0;

    tag = json_object_get(i->json, "tag");
    if (!tag)
        return false;

    if (jose_b64_dec(tag, NULL, 0) != sizeof(tg))
        return false;

    if (jose_b64_dec(tag, tg, sizeof(tg)) != sizeof(tg))
        return false;

    if (EVP_CIPHER_CTX_ctrl(i->cctx, EVP_CTRL_GCM_SET_TAG,
                            sizeof(tg), tg) <= 0)
        return false;

    if (EVP_DecryptFinal(i->cctx, pt, &l) <= 0)
        return false;

    if (!i->next->feed(i->next, pt, l) || !i->next->done(i->next)) {
        OPENSSL_cleanse(pt, sizeof(pt));
        return false;
    }

    OPENSSL_cleanse(pt, sizeof(pt));
    return true;
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

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
    default: return NULL;
    }

    return json_pack("{s:{s:s,s:I}}", "upd", "kty", "oct", "bytes", len);
}

static const char *
alg_encr_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *cek)
{
    const char *name = NULL;
    const char *type = NULL;

    if (json_unpack((json_t *) cek, "{s?s,s?s}",
                    "alg", &name, "kty", &type) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "oct") != 0)
        return NULL;

    switch (jose_b64_dec(json_object_get(cek, "k"), NULL, 0)) {
    case 16: return "A128GCM";
    case 24: return "A192GCM";
    case 32: return "A256GCM";
    default: return NULL;
    }
}

static jose_io_t *
alg_encr_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             const json_t *cek, jose_io_t *next)
{
    const EVP_CIPHER *cph = NULL;
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return NULL;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];

    if (RAND_bytes(iv, sizeof(iv)) <= 0)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = enc_feed;
    io->done = enc_done;
    io->free = io_free;

    i->json = json_incref(jwe);
    i->next = jose_io_incref(next);
    i->cctx = setup(cph, cfg, jwe, cek, iv,
                      EVP_EncryptInit_ex, EVP_EncryptUpdate);
    if (!i->json || !i->next || !i->cctx)
        return NULL;

    if (json_object_set_new(jwe, "iv", jose_b64_enc(iv, sizeof(iv))) < 0)
        return NULL;

    return jose_io_incref(io);
}

static jose_io_t *
alg_encr_dec(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *cek, jose_io_t *next)
{
    const EVP_CIPHER *cph = NULL;
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return NULL;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];

    if (jose_b64_dec(json_object_get(jwe, "iv"), NULL, 0) != sizeof(iv))
        return NULL;

    if (jose_b64_dec(json_object_get(jwe, "iv"), iv, sizeof(iv)) != sizeof(iv))
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = dec_feed;
    io->done = dec_done;
    io->free = io_free;

    i->json = json_incref((json_t *) jwe);
    i->next = jose_io_incref(next);
    i->cctx = setup(cph, cfg, jwe, cek, iv,
                      EVP_DecryptInit_ex, EVP_DecryptUpdate);
    if (!i->json || !i->next || !i->cctx)
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
        { .kind = JOSE_HOOK_ALG_KIND_ENCR,
          .name = "A128GCM",
          .encr.eprm = "encrypt",
          .encr.dprm = "decrypt",
          .encr.sug = alg_encr_sug,
          .encr.enc = alg_encr_enc,
          .encr.dec = alg_encr_dec },
        { .kind = JOSE_HOOK_ALG_KIND_ENCR,
          .name = "A192GCM",
          .encr.eprm = "encrypt",
          .encr.dprm = "decrypt",
          .encr.sug = alg_encr_sug,
          .encr.enc = alg_encr_enc,
          .encr.dec = alg_encr_dec },
        { .kind = JOSE_HOOK_ALG_KIND_ENCR,
          .name = "A256GCM",
          .encr.eprm = "encrypt",
          .encr.dprm = "decrypt",
          .encr.sug = alg_encr_sug,
          .encr.enc = alg_encr_enc,
          .encr.dec = alg_encr_dec },
        {}
    };

    jose_hook_jwk_push(&jwk);
    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}
