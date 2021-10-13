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

const char *const pts[] = {
    "",
    "abc",
    "aosidmfoasidhtaoirnigaoiurebxlicjnvalsiouerhnoaiusdnvaisudfrhpqowuiefnali",
    NULL
};

static void
test(const jose_hook_alg_t *a, const char *pt, json_t *cek, bool iter)
{
    json_auto_t *jwe = json_object();
    jose_io_auto_t *eb = NULL;
    jose_io_auto_t *db = NULL;
    jose_io_auto_t *e = NULL;
    jose_io_auto_t *d = NULL;
    void *ebuf = NULL;
    void *dbuf = NULL;
    size_t elen = 0;
    size_t dlen = 0;

    eb = jose_io_malloc(NULL, &ebuf, &elen);
    assert(eb);
    e = a->encr.enc(a, NULL, jwe, cek, eb);
    assert(e);

    if (iter) {
        for (size_t i = 0; pt[i]; i++)
            assert(e->feed(e, &pt[i], 1));
    } else {
        assert(e->feed(e, pt, strlen(pt)));
    }

    assert(e->done(e));


    assert(json_object_get(jwe, "tag"));


    db = jose_io_malloc(NULL, &dbuf, &dlen);
    assert(db);
    d = a->encr.dec(a, NULL, jwe, cek, db);
    assert(d);

    if (iter) {
        uint8_t *xxx = ebuf;
        for (size_t i = 0; i < elen; i++)
            assert(d->feed(d, &xxx[i], 1));
    } else {
        assert(d->feed(d, ebuf, elen));
    }

    assert(d->done(d));
    assert(dlen == strlen(pt));
    assert(memcmp(pt, dbuf, dlen) == 0);
}

int
main(int argc, char *argv[])
{
    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        json_auto_t *cek = NULL;

        if (a->kind != JOSE_HOOK_ALG_KIND_ENCR)
            continue;

        fprintf(stderr, "alg: %s\n", a->name);

        assert((cek = json_pack("{s:s}", "alg", a->name)));
        assert(jose_jwk_gen(NULL, cek));

        for (size_t i = 0; pts[i]; i++) {
            test(a, pts[i], cek, false);
            test(a, pts[i], cek, true);
        }
    }

    return EXIT_SUCCESS;
}
