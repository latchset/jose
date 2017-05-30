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

#define NAMES "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"

typedef struct {
    jose_io_t io;

    EVP_CIPHER_CTX *cctx;
    jose_io_t *next;
    HMAC_CTX *hctx;
    json_t *json;
    uint64_t al;
} io_t;

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
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return NULL;
    }

    return json_pack("{s{s:s,s:I}}", "upd", "kty", "oct", "bytes", len);
}

static const char *
alg_encr_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *cek)
{
    const char *name = NULL;
    const char *type = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) cek, "{s?s,s?s}",
                    "alg", &name, "kty", &type) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "oct") != 0)
        return NULL;

    len = jose_b64_dec(json_object_get(cek, "k"), NULL, 0);

    if (len >= SHA512_DIGEST_LENGTH)
        return "A256CBC-HS512";
    else if (len >= SHA384_DIGEST_LENGTH)
        return "A192CBC-HS384";
    else if (len >= SHA256_DIGEST_LENGTH)
        return "A128CBC-HS256";

    return NULL;
}

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    EVP_CIPHER_CTX_free(i->cctx);
    jose_io_decref(i->next);
    HMAC_CTX_free(i->hctx);
    json_decref(i->json);
    free(i);
}

static bool
enc_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);

    uint8_t ct[EVP_CIPHER_CTX_block_size(i->cctx) + 1];
    const uint8_t *pt = in;

    for (size_t j = 0; j < len; j++) {
        int l = 0;

        if (EVP_EncryptUpdate(i->cctx, ct, &l, &pt[j], 1) <= 0)
            return false;

        if (!i->next->feed(i->next, ct, l))
            return false;

        if (HMAC_Update(i->hctx, ct, l) <= 0)
            return false;
    }

    return true;
}

static bool
enc_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t ct[EVP_CIPHER_CTX_block_size(i->cctx) + 1];
    uint8_t tg[EVP_MD_size(HMAC_CTX_get_md(i->hctx))];
    int l = 0;

    if (EVP_EncryptFinal(i->cctx, ct, &l) <= 0)
        return false;

    if (!i->next->feed(i->next, ct, l) || !i->next->done(i->next))
        return false;

    if (HMAC_Update(i->hctx, ct, l) <= 0)
        return false;

    if (HMAC_Update(i->hctx, (void *) &i->al, sizeof(i->al)) <= 0)
        return false;

    if (HMAC_Final(i->hctx, tg, NULL) <= 0)
        return false;

    if (json_object_set_new(i->json, "tag",
                            jose_b64_enc(tg, sizeof(tg) / 2)) < 0)
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

    if (HMAC_Update(i->hctx, in, len) <= 0)
        return false;

    for (size_t j = 0; j < len; j++) {
        if (EVP_DecryptUpdate(i->cctx, pt, &l, &ct[j], 1) <= 0)
            goto egress;

        if (!i->next->feed(i->next, pt, l))
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
    uint8_t tg[EVP_MD_size(HMAC_CTX_get_md(i->hctx))];
    uint8_t bf[sizeof(tg) / 2];
    json_t *tag = NULL;
    int l = 0;

    tag = json_object_get(i->json, "tag");
    if (!tag)
        return false;

    if (jose_b64_dec(tag, NULL, 0) != sizeof(bf))
        return false;

    if (jose_b64_dec(tag, bf, sizeof(bf)) != sizeof(bf))
        return false;

    if (HMAC_Update(i->hctx, (void *) &i->al, sizeof(i->al)) <= 0)
        return false;

    if (HMAC_Final(i->hctx, tg, NULL) <= 0)
        return false;

    if (CRYPTO_memcmp(tg, bf, sizeof(bf)) != 0)
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
setup(const EVP_CIPHER *cph, const EVP_MD *md, jose_cfg_t *cfg,
      const json_t *jwe, const json_t *cek, uint8_t *iv,
      typeof(EVP_EncryptInit) func, io_t *i)
{
    uint8_t key[EVP_CIPHER_key_length(cph) * 2];
    const char *aad = NULL;
    const char *prt = "";

    if (jose_b64_dec(json_object_get(cek, "k"), NULL, 0) != sizeof(key))
        return false;

    if (json_unpack((json_t *) jwe, "{s?s,s?s}",
                    "aad", &aad, "protected", &prt) < 0)
        return false;

    i->cctx = EVP_CIPHER_CTX_new();
    if (!i->cctx)
        return false;

    i->hctx = HMAC_CTX_new();
    if (!i->hctx)
        return false;

    if (jose_b64_dec(json_object_get(cek, "k"), NULL, 0) != sizeof(key))
        return false;

    if (jose_b64_dec(json_object_get(cek, "k"), key,
                     sizeof(key)) != sizeof(key)) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    if (HMAC_Init_ex(i->hctx, key, sizeof(key) / 2, md, NULL) <= 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    if (func(i->cctx, cph, &key[sizeof(key) / 2], iv) <= 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    OPENSSL_cleanse(key, sizeof(key));

    i->al += strlen(prt);
    if (HMAC_Update(i->hctx, (void *) prt, strlen(prt)) <= 0)
        return false;

    if (aad) {
        i->al += 1;
        if (HMAC_Update(i->hctx, (void *) ".", 1) <= 0)
            return false;

        i->al += strlen(aad);
        if (HMAC_Update(i->hctx, (void *) aad, strlen(aad)) <= 0)
            return false;
    }

    i->al = htobe64(i->al * 8);

    if (HMAC_Update(i->hctx, iv, EVP_CIPHER_iv_length(cph)) <= 0)
        return false;

    return true;
}

static jose_io_t *
alg_encr_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             const json_t *cek, jose_io_t *next)
{
    const EVP_CIPHER *cph = NULL;
    jose_io_auto_t *io = NULL;
    const EVP_MD *md = NULL;
    io_t *i = NULL;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
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
    if (!i->json || !i->next)
        return NULL;

    if (!setup(cph, md, cfg, jwe, cek, iv, EVP_EncryptInit, i))
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
    const EVP_MD *md = NULL;
    io_t *i = NULL;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
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
    if (!i->json || !i->next)
        return NULL;

    if (!setup(cph, md, cfg, jwe, cek, iv, EVP_DecryptInit, i))
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
          .name = "A128CBC-HS256",
          .encr.eprm = "encrypt",
          .encr.dprm = "decrypt",
          .encr.sug = alg_encr_sug,
          .encr.enc = alg_encr_enc,
          .encr.dec = alg_encr_dec },
        { .kind = JOSE_HOOK_ALG_KIND_ENCR,
          .name = "A192CBC-HS384",
          .encr.eprm = "encrypt",
          .encr.dprm = "decrypt",
          .encr.sug = alg_encr_sug,
          .encr.enc = alg_encr_enc,
          .encr.dec = alg_encr_dec },
        { .kind = JOSE_HOOK_ALG_KIND_ENCR,
          .name = "A256CBC-HS512",
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
