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

const struct {
    const char *alg;
    const char *inf;
    const char *def;
} tests[] = {
    { /* RFC 7520 5.9 */
        .alg = "DEF",
        .inf = "WW91IGNhbiB0cnVzdCB1cyB0byBzdGljayB3aXRoIHlvdSB0aHJvdWdoIHRoaW"
               "NrIGFuZCB0aGlu4oCTdG8gdGhlIGJpdHRlciBlbmQuIEFuZCB5b3UgY2FuIHRy"
               "dXN0IHVzIHRvIGtlZXAgYW55IHNlY3JldCBvZiB5b3Vyc-KAk2Nsb3NlciB0aG"
               "FuIHlvdSBrZWVwIGl0IHlvdXJzZWxmLiBCdXQgeW91IGNhbm5vdCB0cnVzdCB1"
               "cyB0byBsZXQgeW91IGZhY2UgdHJvdWJsZSBhbG9uZSwgYW5kIGdvIG9mZiB3aX"
               "Rob3V0IGEgd29yZC4gV2UgYXJlIHlvdXIgZnJpZW5kcywgRnJvZG8u",
        .def = "bY_BDcIwDEVX-QNU3QEOrIA4pqlDokYxchxVvbEDGzIJbioOSJwc-f___HPjBu"
               "8KVFpVtAplVE1-wZo0YjNZo3C7R5v72pV5f5X382VWjYQpqZKAyjziZOr2B7kQ"
               "PSy6oZIXUnDYbVKN4jNXi2u0yB7t1qSHTjmMODf9QgvrDzfTIQXnyQRuUya4zI"
               "WG3vTOdir0v7BRHFYWq3k1k1A_gSDJqtcBF-GZxw8"
    },
    {}
};

typedef typeof(((jose_hook_alg_t *) NULL)->comp.inf) comp_func_t;

static void
test(const jose_hook_alg_t *a, comp_func_t func, bool iter,
     const uint8_t *i, size_t il,
     const uint8_t *o, size_t ol)
{
    jose_io_auto_t *b = NULL;
    jose_io_auto_t *z = NULL;
    void *buf = NULL;
    size_t len = 0;

    b = jose_io_malloc(NULL, &buf, &len);
    assert(b);

    z = func(a, NULL, b);
    assert(z);

    if (iter) {
        for (size_t j = 0; j < il; j++)
            assert(z->feed(z, &i[j], 1));
    } else {
        assert(z->feed(z, i, il));
    }

    assert(z->done(z));

    assert(len == ol);
    assert(memcmp(buf, o, ol) == 0);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; tests[i].alg; i++) {
        const size_t ilen = jose_b64_dec_buf(NULL, strlen(tests[i].inf), NULL, 0);
        const size_t dlen = jose_b64_dec_buf(NULL, strlen(tests[i].def), NULL, 0);
        const jose_hook_alg_t *a = NULL;

        assert(ilen != SIZE_MAX);
        assert(dlen != SIZE_MAX);

        uint8_t tst_inf[ilen];
        uint8_t tst_def[dlen];

        assert((a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_COMP, tests[i].alg)));

        assert(jose_b64_dec_buf(tests[i].inf, strlen(tests[i].inf),
                                tst_inf, sizeof(tst_inf)) == sizeof(tst_inf));
        assert(jose_b64_dec_buf(tests[i].def, strlen(tests[i].def),
                                tst_def, sizeof(tst_def)) == sizeof(tst_def));

        test(a, a->comp.def, false,
             tst_inf, sizeof(tst_inf),
             tst_def, sizeof(tst_def));

        test(a, a->comp.inf, false,
             tst_def, sizeof(tst_def),
             tst_inf, sizeof(tst_inf));

        test(a, a->comp.def, true,
             tst_inf, sizeof(tst_inf),
             tst_def, sizeof(tst_def));

        test(a, a->comp.inf, true,
             tst_def, sizeof(tst_def),
             tst_inf, sizeof(tst_inf));
    }

    return EXIT_SUCCESS;
}
