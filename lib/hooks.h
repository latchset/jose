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

#pragma once

#include <jose/jws.h>
#include <jose/jwe.h>

typedef enum {
    JOSE_HOOK_JWK_KIND_NONE = 0,
    JOSE_HOOK_JWK_KIND_TYPE,
    JOSE_HOOK_JWK_KIND_OPER,
    JOSE_HOOK_JWK_KIND_PREP,
    JOSE_HOOK_JWK_KIND_MAKE,
    JOSE_HOOK_JWK_KIND_LAST = JOSE_HOOK_JWK_KIND_MAKE
} jose_hook_jwk_kind_t;

typedef enum {
    JOSE_HOOK_ALG_KIND_NONE = 0,
    JOSE_HOOK_ALG_KIND_HASH,
    JOSE_HOOK_ALG_KIND_SIGN,
    JOSE_HOOK_ALG_KIND_WRAP,
    JOSE_HOOK_ALG_KIND_ENCR,
    JOSE_HOOK_ALG_KIND_COMP,
    JOSE_HOOK_ALG_KIND_EXCH,
    JOSE_HOOK_ALG_KIND_LAST = JOSE_HOOK_ALG_KIND_EXCH
} jose_hook_alg_kind_t;

typedef struct jose_hook_jwk jose_hook_jwk_t;
struct jose_hook_jwk {
    const jose_hook_jwk_t *next;
    jose_hook_jwk_kind_t kind;

    union {
        struct {
            const char  *kty;
            const char **req;
            const char **pub;
            const char **prv;
        } type;

        struct {
            const char *pub;
            const char *prv;
            const char *use;
        } oper;

        struct {
            bool
            (*handles)(jose_cfg_t *cfg, const json_t *jwk);

            json_t *
            (*execute)(jose_cfg_t *cfg, const json_t *jwk);
        } prep;

        struct {
            bool
            (*handles)(jose_cfg_t *cfg, const json_t *jwk);

            json_t *
            (*execute)(jose_cfg_t *cfg, const json_t *jwk);
        } make;
    };
};

typedef struct jose_hook_alg jose_hook_alg_t;
struct jose_hook_alg {
    const jose_hook_alg_t *next;
    jose_hook_alg_kind_t kind;
    const char *name;

    union {
        struct {
            size_t size;

            jose_io_t *
            (*hsh)(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next);
        } hash;

        struct {
            const char *sprm;
            const char *vprm;

            const char *
            (*sug)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jwk);

            jose_io_t *
            (*sig)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   json_t *jws, json_t *sig, const json_t *jwk);

            jose_io_t *
            (*ver)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jws, const json_t *sig, const json_t *jwk);
        } sign;

        struct {
            const char *eprm;
            const char *dprm;

            const char *
            (*alg)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jwk);

            const char *
            (*enc)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jwk);

            bool
            (*wrp)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   json_t *jwe, json_t *rcp,
                   const json_t *jwk, json_t *cek);

            bool
            (*unw)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jwe, const json_t *rcp,
                   const json_t *jwk, json_t *cek);
        } wrap;

        struct {
            const char *eprm;
            const char *dprm;

            const char *
            (*sug)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *cek);

            jose_io_t *
            (*enc)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   json_t *jwe, const json_t *cek, jose_io_t *next);

            jose_io_t *
            (*dec)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *jwe, const json_t *cek, jose_io_t *next);
        } encr;

        struct {
            jose_io_t *
            (*def)(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next);

            jose_io_t *
            (*inf)(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next);
        } comp;

        struct {
            const char *prm;

            const char *
            (*sug)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *prv, const json_t *pub);

            json_t *
            (*exc)(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
                   const json_t *prv, const json_t *pub);
        } exch;
    };
};

void
jose_hook_jwk_push(jose_hook_jwk_t *reg);

const jose_hook_jwk_t *
jose_hook_jwk_list(void);

void
jose_hook_alg_push(jose_hook_alg_t *alg);

const jose_hook_alg_t *
jose_hook_alg_list(void);

const jose_hook_alg_t *
jose_hook_alg_find(jose_hook_alg_kind_t kind, const char *name);
