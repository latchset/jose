/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "hmac.h"
#include "vect.h"
#include "jwk.h"
#include "jws.h"
#include "b64.h"

#include <assert.h>
#include <string.h>

static const struct {
    const char *key;
    const char *data;
    const char *s256;
    const char *s384;
    const char *s512;
} rfc4231[] = {
    /* RFC 4231 4.2 */
    { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There",
      .s256 = "b0344c61d8db38535ca8afceaf0bf12b"
              "881dc200c9833da726e9376c2e32cff7",
      .s384 = "afd03944d84895626b0825f4ab46907f"
              "15f9dadbe4101ec682aa034c7cebc59c"
              "faea9ea9076ede7f4af152e8b2fa9cb6",
      .s512 = "87aa7cdea5ef619d4ff0b4241a1d6cb0"
              "2379f4e2ce4ec2787ad0b30545e17cde"
              "daa833b7d6b8a702038b274eaea3f4e4"
              "be9d914eeb61f1702e696c203a126854" },

    /* RFC 4231 4.3 */
    { "4a656665", "what do ya want for nothing?",
      .s256 = "5bdcc146bf60754e6a042426089575c7"
              "5a003f089d2739839dec58b964ec3843",
      .s384 = "af45d2e376484031617f78d2b58a6b1b"
              "9c7ef464f5a01b47e42ec3736322445e"
              "8e2240ca5e69e2c78b3239ecfab21649",
      .s512 = "164b7a7bfcf819e2e395fbe73b56e0a3"
              "87bd64222e831fd610270cd7ea250554"
              "9758bf75c05a994a6d034f65f8f0e6fd"
              "caeab1a34d4a6b4b636e070a38bce737" },

    /* RFC 4231 4.6 */
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      .s256 = "60e431591ee0b67f0d8a26aacbf5b77f"
              "8e0bc6213728c5140546040f0ee37f54",
      .s384 = "4ece084485813e9088d2c63a041bc5b4"
              "4f9ef1012a2b588f3cd11f05033ac4c6"
              "0c2ef6ab4030fe8296248df163f44952",
      .s512 = "80b24263c7c1a3ebb71493c1dd7be8b4"
              "9b46d1f41b4aeec1121b013783f8f352"
              "6b56d037e05f2598bd0fd2215d6a1e52"
              "95e64f73f63f0aec8b915a985d786598", },

    /* RFC 4231 4.7 */
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "This is a test using a larger than block-size key "
      "and a larger than block-size data. The key needs to "
      "be hashed before being used by the HMAC algorithm.",
      .s256 = "9b09ffa71b942fcb27635fbcd5b0e944"
              "bfdc63644f0713938a7f51535c3a35e2",
      .s384 = "6617178e941f020d351e2f254e8fd32c"
              "602420feb0b8fb9adccebb82461e99c5"
              "a678cc31e799176d3860e6110c46523e",
      .s512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
              "debd71f8867289865df5a32d20cdc944"
              "b6022cac3c4982b10d5eeb55c3e4de15"
              "134676fb6de0446065c97440fa8c6a58", },

    {}
};

static const struct {
    const char *rfc;
    const char *alg;
} jose[] = {
    { "rfc7515_A.1", "HS256" },
    { "rfc7520_4.4", "HS256", },
    {}
};

static bool
hexchr(char i, uint8_t *o)
{
    switch (i) {
    case '0': *o |= 0x0; return true;
    case '1': *o |= 0x1; return true;
    case '2': *o |= 0x2; return true;
    case '3': *o |= 0x3; return true;
    case '4': *o |= 0x4; return true;
    case '5': *o |= 0x5; return true;
    case '6': *o |= 0x6; return true;
    case '7': *o |= 0x7; return true;
    case '8': *o |= 0x8; return true;
    case '9': *o |= 0x9; return true;
    case 'a': *o |= 0xa; return true;
    case 'A': *o |= 0xA; return true;
    case 'b': *o |= 0xb; return true;
    case 'B': *o |= 0xB; return true;
    case 'c': *o |= 0xc; return true;
    case 'C': *o |= 0xC; return true;
    case 'd': *o |= 0xd; return true;
    case 'D': *o |= 0xD; return true;
    case 'e': *o |= 0xe; return true;
    case 'E': *o |= 0xE; return true;
    case 'f': *o |= 0xf; return true;
    case 'F': *o |= 0xF; return true;
    default: return false;
    }
}

static bool
hexdec(const char *enc, uint8_t dec[])
{
    size_t len = 0;

    len = strlen(enc);
    for (size_t i = 0; i < len / 2; i++) {
        dec[i] = 0;
        if (!hexchr(enc[i * 2], &dec[i]))
            return false;

        dec[i] <<= 4;
        if (!hexchr(enc[i * 2 + 1], &dec[i]))
            return false;
    }

    return true;
}

static void
test(const EVP_MD *md, const uint8_t *key, size_t len, const char *data, const char *res)
{
        uint8_t buf[EVP_MD_size(md)];
        uint8_t hex[strlen(res) / 2];


        assert(hmac(md, key, len, buf, data, NULL));
        assert(hexdec(res, hex));
        assert(memcmp(buf, hex, sizeof(buf)) == 0);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; rfc4231[i].key; i++) {
        uint8_t key[strlen(rfc4231[i].key) / 2];

        assert(hexdec(rfc4231[i].key, key));

        fprintf(stderr, "================= %zu S256 ==================\n", i);
        test(EVP_sha256(), key, sizeof(key), rfc4231[i].data, rfc4231[i].s256);

        fprintf(stderr, "================= %zu S256 ==================\n", i);
        test(EVP_sha384(), key, sizeof(key), rfc4231[i].data, rfc4231[i].s384);

        fprintf(stderr, "================= %zu S256 ==================\n", i);
        test(EVP_sha512(), key, sizeof(key), rfc4231[i].data, rfc4231[i].s512);
    }

    for (size_t i = 0; jose[i].rfc; i++) {
        const char *prot = NULL;
        const char *payl = NULL;
        EVP_PKEY *key = NULL;
        uint8_t *sig = NULL;
        json_t *jwk = NULL;
        json_t *jws = NULL;
        json_t *xxx = NULL;
        char *tmp = NULL;
        size_t len = 0;

        fprintf(stderr, "================= %s ==================\n",
                jose[i].rfc);

        jwk = vect_json(jose[i].rfc, "jwk");
        assert(jwk);

        key = jose_jwk_to_key(jwk);
        json_decref(jwk);
        assert(key);

        tmp = vect_str(jose[i].rfc, "jwsc");
        assert(tmp);

        jws = jose_jws_from_compact(tmp);
        free(tmp);
        assert(jws);

        assert(json_unpack(jws, "{s:s,s:s}", "payload", &payl,
                           "protected", &prot) == 0);

        sig = hmac_sign(jose[i].alg, key, prot, payl, &len);
        assert(sig);

        xxx = jose_b64_encode_json(sig, len);
        assert(xxx);

        assert(json_equal(xxx, json_object_get(jws, "signature")));
        json_decref(xxx);

        assert(hmac_verify(jose[i].alg, key, prot, payl, sig, len));

        sig[1] = sig[1] + 1;

        assert(!hmac_verify(jose[i].alg, key, prot, payl, sig, len));
        EVP_PKEY_free(key);
        json_decref(jws);
        free(sig);
    }

    return 0;
}
