/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwe.h"
#include "b64.h"
#include "vect.h"

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

static const char *vectors[] = {
    "rfc7520_5.1",
    "rfc7520_5.2",
    NULL
};


static void
test_decrypt(const json_t *jwe, const jose_buf_t *cek)
{
    jose_buf_t *pt = NULL;
    pt = jose_jwe_decrypt(jwe, cek);
    assert(pt);
    assert(pt->used == strlen(plaintext));
    assert(memcmp(pt->data, plaintext, pt->used) == 0);
    jose_buf_free(pt);
}

static void
test_unseal(const json_t *jwe, const jose_buf_t *cek, const json_t *jwk)
{
    jose_buf_t *tmp = NULL;
    tmp = jose_jwe_unseal_jwk(jwe, jwk);
    assert(tmp);
    assert(cek->used == tmp->used);
    assert(memcmp(cek->data, tmp->data, cek->used) == 0);
    jose_buf_free(tmp);
}

int
main(int argc, char *argv[])
{
    static char *types[] = { "jweg", "jwef", "jwec", NULL };

    for (size_t i = 0; vectors[i]; i++) {
        for (size_t j = 0; types[j]; j++) {
            jose_buf_t *cek = NULL;
            json_t *prot = NULL;
            json_t *shrd = NULL;
            json_t *head = NULL;
            json_t *jwe = NULL;
            json_t *jwk = NULL;
            json_t *p = NULL;

            fprintf(stderr, "%s %s\n", vectors[i], types[j]);

            if (strcmp(types[j], "jwec") == 0) {
                char *a = NULL;
                char *b = NULL;

                a = vect_str(vectors[i], types[j]);
                assert(a);

                jwe = jose_jwe_from_compact(a);
                assert(json_is_object(jwe));

                b = jose_jwe_to_compact(jwe);
                assert(b);

                assert(strcmp(a, b) == 0);
                free(a);
                free(b);
            } else {
                jwe = vect_json(vectors[i], "jweg");
                assert(jwe);
            }

            /* First, ensure that decrypt works with the hard-coded CEK. */
            cek = vect_b64(vectors[i], "cek");
            assert(cek);
            test_decrypt(jwe, cek);

            /* Next, ensure that unseal produces the hard-coded CEK. */
            jwk = vect_json(vectors[i], "jwk");
            assert(jwk);
            test_unseal(jwe, cek, jwk);

            /* Now, let's extract the headers so we can attempt to recreate
             * the encryption/signing process. */
            if (strcmp(types[j], "jweg") == 0) {
                assert(json_unpack(jwe, "{s? O, s? O, s? [{s? O}!]}",
                                   "protected", &prot,
                                   "unprotected", &shrd,
                                   "recipients", "header", &head) == 0);
            } else {
                assert(json_unpack(jwe, "{s? O, s? O, s? O}",
                                   "protected", &prot,
                                   "unprotected", &shrd,
                                   "header", &head) == 0);
            }
            p = jose_b64_decode_json_load(prot, 0);
            assert(!prot || p);
            json_decref(prot);

            json_decref(jwe);
            jwe = json_object();
            assert(jwe);

            assert(jose_jwe_encrypt(jwe, p, shrd, (uint8_t *) plaintext,
                                    strlen(plaintext), &cek));

            jose_buf_free(cek);
            json_decref(shrd);
            json_decref(head);
            json_decref(jwe);
            json_decref(jwk);
            json_decref(p);
        }
    }

    return 0;
}
