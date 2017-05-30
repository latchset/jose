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

const char *payloads[] = {
    "",
    "abc",
    "aosidmfoasidhtaoirnigaoiurebxlicjnvalsiouerhnoaiusdnvaisudfrhpqowuiefnali",
    NULL
};

static void
test(const jose_hook_alg_t *a, const char *pay, json_t *jwk, bool iter)
{
    json_auto_t *jwe = json_object();
    json_auto_t *rcp = json_object();
    jose_io_auto_t *sio = NULL;
    jose_io_auto_t *vio = NULL;

    sio = a->sign.sig(a, NULL, jwe, rcp, jwk);
    assert(sio);
    if (iter) {
        assert(sio->feed(sio, pay, strlen(pay)));
    } else {
        for (size_t i = 0; pay[i]; i++)
            assert(sio->feed(sio, &pay[i], 1));
    }
    assert(sio->done(sio));

    assert(json_object_get(jwe, "signature"));

    vio = a->sign.ver(a, NULL, jwe, jwe, jwk);
    assert(vio);
    if (iter) {
        assert(vio->feed(vio, pay, strlen(pay)));
    } else {
        for (size_t i = 0; pay[i]; i++)
            assert(vio->feed(vio, &pay[i], 1));
    }
    assert(vio->done(vio));
}

int
main(int argc, char *argv[])
{
    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        json_auto_t *jwk = NULL;

        if (a->kind != JOSE_HOOK_ALG_KIND_SIGN)
            continue;

        fprintf(stderr, "alg: %s\n", a->name);

        assert((jwk = json_pack("{s:s}", "alg", a->name)));
        assert(jose_jwk_gen(NULL, jwk));

        for (size_t i = 0; payloads[i]; i++) {
            test(a, payloads[i], jwk, false);
            test(a, payloads[i], jwk, true);
        }
    }

    return EXIT_SUCCESS;
}
