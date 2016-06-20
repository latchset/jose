/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwe.h"
#include "b64.h"
#include "conv.h"
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
} vectors[] = {
    { "rfc7520_5.1", "jwec" },
    { "rfc7520_5.1", "jwef" },
    { "rfc7520_5.1", "jweg" },
    { "rfc7520_5.2", "jwec" },
    { "rfc7520_5.2", "jwef" },
    { "rfc7520_5.2", "jweg" },
    {}
};

static EVP_PKEY *
load_cek(const char *name)
{
    jose_buf_t *buf = NULL;
    EVP_PKEY *cek = NULL;

    buf = vect_b64(name, "cek");
    assert(buf);

    cek = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf->data, buf->used);
    jose_buf_free(buf);
    return cek;
}

static void
test_decrypt(const json_t *jwe, EVP_PKEY *cek)
{
    jose_buf_t *pt = NULL;
    pt = jose_jwe_decrypt(jwe, cek);
    assert(pt);
    assert(pt->used == strlen(plaintext));
    assert(memcmp(pt->data, plaintext, pt->used) == 0);
    jose_buf_free(pt);
}

static void
test_unseal(const json_t *jwe, EVP_PKEY *cek, const json_t *jwk)
{
    EVP_PKEY *tmp = NULL;
    tmp = jose_jwe_unseal_jwk(jwe, jwk);
    assert(tmp);
    assert(tmp->ameth);
    assert(ASN1_OCTET_STRING_cmp(EVP_PKEY_get0(cek), EVP_PKEY_get0(tmp)) == 0);
    EVP_PKEY_free(tmp);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].name; i++) {
        EVP_PKEY *cek = NULL;
        json_t *jwe = NULL;
        json_t *jwk = NULL;

        fprintf(stderr, "==================== %s (%s) ====================\n",
                vectors[i].name, vectors[i].type);

        if (strcmp(vectors[i].type, "jwec") == 0) {
            char *a = NULL;
            char *b = NULL;

            a = vect_str(vectors[i].name, vectors[i].type);
            assert(a);

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
        cek = load_cek(vectors[i].name);
        assert(cek);
        test_decrypt(jwe, cek);

        /* Next, ensure that unseal produces the hard-coded CEK. */
        jwk = vect_json(vectors[i].name, "jwk");
        assert(jwk);
        test_unseal(jwe, cek, jwk);

        json_object_del(jwe, "encrypted_key");
        json_object_del(jwe, "recipients");
        json_object_del(jwe, "ciphertext");
        json_object_del(jwe, "header");
        json_object_del(jwe, "tag");
        json_object_del(jwe, "iv");

        assert(jose_jwe_encrypt(jwe, cek, (uint8_t *) plaintext,
                                strlen(plaintext)));

        assert(jose_jwe_seal_jwk(jwe, cek, jwk, NULL));

        EVP_PKEY_free(cek);
        json_decref(jwe);
        json_decref(jwk);
    }

    return 0;
}
