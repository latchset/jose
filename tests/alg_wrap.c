/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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

#include "../lib/hooks.h"
#include <jose/jose.h>
#include <assert.h>
#include <string.h>

int
main(int argc, char *argv[])
{
    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);

        if (a->kind != JOSE_HOOK_ALG_KIND_WRAP)
            continue;

        fprintf(stderr, "alg: %s\n", a->name);

        if (strcmp(a->name, "dir") != 0)
            assert(jose_jwk_gen(NULL, jwk));

        for (const jose_hook_alg_t *b = jose_hook_alg_list(); b; b = b->next) {
            json_auto_t *cek = json_pack("{s:s}", "alg", b->name);
            json_auto_t *tst = json_pack("{s:s}", "alg", b->name);
            json_auto_t *rcp = json_object();
            json_auto_t *jwe = json_object();

            if (b->kind != JOSE_HOOK_ALG_KIND_ENCR)
                continue;

            fprintf(stderr, "\tenc: %s\n", b->name);

            if (strcmp(a->name, "dir") == 0) {
                json_decref(jwk);
                assert((jwk = json_deep_copy(cek)));
                assert(jose_jwk_gen(NULL, jwk));
            }

            assert(jose_jwk_gen(NULL, tst));
            assert(json_object_del(tst, "k") == 0);

            assert(a->wrap.wrp(a, NULL, jwe, rcp, jwk, cek));
            assert(a->wrap.unw(a, NULL, jwe, rcp, jwk, tst));
            assert(json_equal(cek, tst));
        }
    }

    return EXIT_SUCCESS;
}
