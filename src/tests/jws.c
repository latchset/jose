/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "../jws.h"
#include "../b64.h"

#include "vect.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

static const struct {
    const char *name;
    const char *ext;
    const char *jwk;
    const char *content;
} vectors[] = {
    { "rfc7515_A.1", "jwsc", "jwk" },
    { "rfc7515_A.2", "jwsc", "jwk" },
    { "rfc7515_A.3", "jwsc", "jwk" },
    { "rfc7515_A.4", "jwsc", "jwk" },
    { "rfc7515_A.5", "jwsc", NULL },
    { "rfc7515_A.6", "jwsg", "jwkset" },
    { "rfc7515_A.7", "jwsf", "jwk" },
    { "rfc7520_4.1", "jwsc", "jwk" },
    { "rfc7520_4.1", "jwsf", "jwk" },
    { "rfc7520_4.1", "jwsg", "jwk" },
    { "rfc7520_4.2", "jwsc", "jwk" },
    { "rfc7520_4.2", "jwsf", "jwk" },
    { "rfc7520_4.2", "jwsg", "jwk" },
    { "rfc7520_4.3", "jwsc", "jwk" },
    { "rfc7520_4.3", "jwsf", "jwk" },
    { "rfc7520_4.3", "jwsg", "jwk" },
    { "rfc7520_4.4", "jwsc", "jwk" },
    { "rfc7520_4.4", "jwsf", "jwk" },
    { "rfc7520_4.4", "jwsg", "jwk" },
    { "rfc7520_4.5", "jwsc", "jwk",
      "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIg"
      "ZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVw"
      "IHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJl"
      "IHN3ZXB0IG9mZiB0by4" },
    { "rfc7520_4.5", "jwsf", "jwk",
      "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIg"
      "ZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVw"
      "IHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJl"
      "IHN3ZXB0IG9mZiB0by4" },
    { "rfc7520_4.5", "jwsg", "jwk",
      "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIg"
      "ZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVw"
      "IHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJl"
      "IHN3ZXB0IG9mZiB0by4" },
    { "rfc7520_4.6", "jwsf", "jwk" },
    { "rfc7520_4.6", "jwsg", "jwk" },
    { "rfc7520_4.7", "jwsf", "jwk" },
    { "rfc7520_4.7", "jwsg", "jwk" },
    { "rfc7520_4.8", "jwsg", "jwkset" },
    {}
};

static void
test(json_t *jws, json_t *jwkset)
{
    json_t *keys = json_object_get(jwkset, "keys");
    json_t *sigs = NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = NULL;
        bool ret = false;
        jwk = json_array_get(keys, i);
        ret = jose_jws_verify(jws, jwk);
        assert(ret);
    }

    sigs = json_incref(json_object_get(jws, "signatures"));
    if (!sigs) {
        json_t *p = NULL;
        json_t *h = NULL;
        json_t *s = NULL;

        assert(!json_unpack(jws, "{s?o,s?o}", "protected", &p, "header", &h));
        assert(sigs = json_pack("[o]", s = json_object()));
        assert(!p || json_object_set(s, "protected", p) == 0);
        assert(!h || json_object_set(s, "header", h) == 0);
    }

    json_object_del(jws, "signatures");
    json_object_del(jws, "signature");
    json_object_del(jws, "protected");
    json_object_del(jws, "header");

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        json_t *sig = json_array_get(sigs, i);

        assert(jose_jws_sign(jws, jwk, json_incref(sig)));

        for (size_t j = 0; j <= i; j++) {
            jwk = json_array_get(keys, i);
            assert(jose_jws_verify(jws, jwk));
        }
    }

    json_decref(sigs);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].name; i++) {
        char *cmpct = NULL;
        json_t *jws = NULL;
        json_t *s = NULL;
        json_t *h = NULL;

        fprintf(stderr, "=================== %s (%s) ===================\n\n",
                vectors[i].name, vectors[i].ext);

        if (strcmp(vectors[i].ext, "jwsc") == 0) {
            cmpct = vect_str(vectors[i].name, vectors[i].ext);
            assert(cmpct);

            jws = jose_jws_from_compact(cmpct);
            free(cmpct);
        } else {
            jws = vect_json(vectors[i].name, vectors[i].ext);
        }

        if (vectors[i].content) {
            assert(json_object_set_new(jws, "payload",
                                       json_string(vectors[i].content)) == 0);
        }

        if (!vectors[i].jwk) {
            json_t *jwk = NULL;
            assert(jwk = json_object());
            assert(!jose_jws_verify(jws, NULL));
            assert(!jose_jws_verify(jws, jwk));
            json_decref(jwk);
        } else {
            json_t *jwkset = NULL;
            json_t *jwk = NULL;

            jwk = vect_json(vectors[i].name, vectors[i].jwk);
            assert(jwk);

            if (strcmp(vectors[i].jwk, "jwkset") != 0)
                jwkset = json_pack("{s:[o]}", "keys", jwk);
            else
                jwkset = jwk;

            assert(jwkset);
            test(jws, jwkset);
            json_decref(jwkset);
        }

        assert(!json_unpack(jws, "{s?o,s?o}", "signatures", &s, "header", &h));
        cmpct = jose_jws_to_compact(jws);
        assert(!!cmpct == (!s && !h));
        free(cmpct);

        json_decref(jws);
    }

    return 0;
}
