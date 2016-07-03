/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/b64.h>
#include <jose/jwe.h>
#include "vect.h"

#include <openssl/evp.h>

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>

static const char plaintext[] =
    "You can trust us to stick with you through thick and "
    "thin–to the bitter end. And you can trust us to "
    "keep any secret of yours–closer than you keep it "
    "yourself. But you cannot trust us to let you face trouble "
    "alone, and go off without a word. We are your friends, Frodo.";

static const struct {
    const char *name;
    const char *type;
    bool dir;
} vectors[] = {
    { "rfc7520_5.1", "jwec" },
    { "rfc7520_5.1", "jwef" },
    { "rfc7520_5.1", "jweg" },
    { "rfc7520_5.2", "jwec" },
    { "rfc7520_5.2", "jwef" },
    { "rfc7520_5.2", "jweg" },
    { "rfc7520_5.6", "jwec", true },
    { "rfc7520_5.6", "jweg", true },
    { "rfc7520_5.7", "jwec" },
    { "rfc7520_5.7", "jwef" },
    { "rfc7520_5.7", "jweg" },
    { "rfc7520_5.8", "jwec" },
    { "rfc7520_5.8", "jwef" },
    { "rfc7520_5.8", "jweg" },
    { "rfc7520_5.9", "jwec" },
    { "rfc7520_5.9", "jwef" },
    { "rfc7520_5.9", "jweg" },
    { "rfc7520_5.10", "jwef" },
    { "rfc7520_5.10", "jweg" },
    { "rfc7520_5.11", "jwef" },
    { "rfc7520_5.11", "jweg" },
    { "rfc7520_5.12", "jwef" },
    { "rfc7520_5.12", "jweg" },
    {}
};

static void
test_decrypt(const json_t *jwe, const json_t *cek)
{
    uint8_t *pt = NULL;
    json_t *ct = NULL;
    size_t ptl = 0;

    ct = json_object_get(jwe, "ciphertext");
    assert(json_is_string(ct));

    assert(pt = jose_jwe_decrypt(jwe, cek, &ptl));
    assert(ptl == strlen(plaintext));
    assert(memcmp(pt, plaintext, ptl) == 0);
    free(pt);
}

static void
test_unseal(const json_t *jwe, const json_t *cek, const json_t *jwk)
{
    json_t *tmp = NULL;
    assert(tmp = jose_jwe_unseal(jwe, jwk));
    assert(json_equal(json_object_get(tmp, "k"), json_object_get(cek, "k")));
    json_decref(tmp);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].name; i++) {
        json_t *cek = NULL;
        json_t *jwe = NULL;
        json_t *jwk = NULL;
        json_t *prt = NULL;

        fprintf(stderr, "==================== %s (%s) ====================\n",
                vectors[i].name, vectors[i].type);

        if (strcmp(vectors[i].type, "jwec") == 0) {
            char *a = NULL;
            char *b = NULL;

            assert(a = vect_str(vectors[i].name, "jwec"));

            jwe = jose_jwe_from_compact(a);
            assert(json_is_object(jwe));

            b = jose_jwe_to_compact(jwe);
            assert(b);

            assert(strcmp(a, b) == 0);
            free(a);
            free(b);
        } else {
            jwe = vect_json(vectors[i].name, vectors[i].type);
            assert(jwe);
        }

        /* First, ensure that decrypt works with the hard-coded CEK. */
        cek = vect_json(vectors[i].name, "cek");
        assert(cek);
        test_decrypt(jwe, cek);

        /* Next, ensure that unseal produces the hard-coded CEK. */
        if (vectors[i].dir)
            jwk = json_incref(cek);
        else
            jwk = vect_json(vectors[i].name, "jwk");
        assert(jwk);
        test_unseal(jwe, cek, jwk);

        /* Now, remove all the automatically generated stuff. */
        prt = json_object_get(jwe, "protected");
        if (prt) {
            assert(prt = jose_b64_decode_json_load(prt));
            assert(json_object_set_new(jwe, "protected", prt) == 0);
        }
        json_object_del(jwe, "encrypted_key");
        json_object_del(jwe, "recipients");
        json_object_del(jwe, "ciphertext");
        json_object_del(jwe, "header");
        json_object_del(jwe, "tag");
        json_object_del(prt, "tag");
        json_object_del(jwe, "iv");
        json_object_del(prt, "iv");

        /* Encrypt and seal. */
        assert(jose_jwe_encrypt(jwe, cek, (uint8_t *) plaintext,
                                strlen(plaintext)));
        assert(jose_jwe_seal(jwe, cek, jwk, NULL));

        /* Test the results of our process. */
        test_unseal(jwe, cek, jwk);
        test_decrypt(jwe, cek);

        json_decref(cek);
        json_decref(jwe);
        json_decref(jwk);
    }

    return 0;
}
