/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/objects.h>

enum type {
    TYPE_NONE = 0,
    TYPE_OCT,
    TYPE_RSA,
    TYPE_EC,
};

struct kv {
    const char *key;
    const char *val;
};

static const struct {
    enum type type;
    struct kv *base;
    struct kv *prvt;
    struct kv *xtra;
} vectors[] = {
    { TYPE_EC, /* RFC 7517 - A.1 */
      (struct kv[]) {
          { "kty", "EC" },
          { "crv", "P-256" },
          { "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4" },
          { "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "use", "enc" },
          { "kid", "1" },
          {}
      } },
    { TYPE_RSA, /* RFC 7517 - A.1 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfA"
                 "AtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhM"
                 "stn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGj"
                 "QR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5"
                 "hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcR"
                 "wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "alg", "RS256" },
          { "kid", "2011-04-29" },
          {}
      } },
    { TYPE_EC, /* RFC 7517 - A.2 */
      (struct kv[]) {
          { "kty", "EC" },
          { "crv", "P-256" },
          { "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4" },
          { "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM" },
          {}
      },
      (struct kv[]) {
          { "d", "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" },
          {}
      },
      (struct kv[]) {
          { "use", "enc" },
          { "kid", "1" },
          {}
      } },
    { TYPE_RSA, /* RFC 7517 - A.2 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfA"
                 "AtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhM"
                 "stn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGj"
                 "QR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5"
                 "hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2Ncr"
                 "wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          { "d", "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5"
                 "oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfq"
                 "ijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYa"
                 "MwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu"
                 "4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4"
                 "j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q" },
          { "p", "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD"
                 "20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIY"
                 "QyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs" },
          { "q", "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjV"
                 "ZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78T"
                 "zFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk" },
          { "dp","G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxI"
                 "i2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_N"
                 "mtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0" },
          { "dq","s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfB"
                 "cMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb"
                 "_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk" },
          { "qi","GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZE"
                 "VFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ1"
                 "1rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU" },
          {}
      },
      (struct kv[]) {
          { "alg", "RS256" },
          { "kid", "2011-04-29" },
          {}
      } },
    { TYPE_OCT, /* RFC 7517 - A.3 */
      (struct kv[]) {
          { "kty", "oct" },
          {}
      },
      (struct kv[]) {
          { "k", "GawgguFyGrWKav7AX4VKUg" },
          {}
      },
      (struct kv[]) {
          { "alg", "A128KW" },
          {}
      } },
    { TYPE_OCT, /* RFC 7517 - A.3 */
      (struct kv[]) {
          { "kty", "oct" },
          {}
      },
      (struct kv[]) {
          { "k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_"
                 "T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" },
          {}
      },
      (struct kv[]) {
          { "kid", "HMAC key used in JWS spec Appendix A.1 example" },
          {}
      } },
    { TYPE_RSA, /* RFC 7517 - B (x5c parameter omitted) */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PL"
                 "bK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0"
                 "Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxT"
                 "Wq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wg"
                 "zjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPd"
                 "wS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "use", "sig" },
          { "kid", "1b94c" },
          {}
      } },
    { TYPE_RSA, /* RFC 7517 - C.1 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMS"
                 "QRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom"
                 "-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jC"
                 "tLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2Zil"
                 "gT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15"
                 "_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          { "d", "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTy"
                 "WfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdl"
                 "PKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNn"
                 "PiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqAD"
                 "C6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1"
                 "yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ" },
          { "p", "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-P"
                 "IHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk"
                 "31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws" },
          { "q", "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0"
                 "c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV"
                 "8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s" },
          { "dp","KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVD"
                 "q3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_"
                 "kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c" },
          { "dq","AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkb"
                 "N9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3"
                 "KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots" },
          { "qi","lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmU"
                 "qqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm"
                 "-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8" },
          {}
      },
      (struct kv[]) {
          { "kid", "juliet@capulet.lit" },
          { "use", "enc" },
          {}
      } },
    {}
};

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].type != TYPE_NONE; i++) {
        json_t *kbase = NULL;
        json_t *kprvt = NULL;
        json_t *kxtra = NULL;
        json_t *cbase = NULL;
        json_t *cprvt = NULL;
        json_t *prvt = NULL;

        kbase = json_object();
        kprvt = json_object();
        kxtra = json_object();
        assert(kbase);
        assert(kprvt);
        assert(kxtra);

        for (size_t j = 0; vectors[i].base[j].key; j++) {
            const char *k = vectors[i].base[j].key;
            const char *v = vectors[i].base[j].val;
            assert(json_object_set_new(kbase, k, json_string(v)) != -1);
            assert(json_object_set_new(kprvt, k, json_string(v)) != -1);
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        for (size_t j = 0; vectors[i].prvt[j].key; j++) {
            const char *k = vectors[i].prvt[j].key;
            const char *v = vectors[i].prvt[j].val;
            assert(json_object_set_new(kprvt, k, json_string(v)) != -1);
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        for (size_t j = 0; vectors[i].xtra[j].key; j++) {
            const char *k = vectors[i].xtra[j].key;
            const char *v = vectors[i].xtra[j].val;
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        switch (vectors[i].type) {
        case TYPE_OCT: {
            jose_key_t *key = NULL;

            key = jose_jwk_to_key(kxtra);
            assert(key);

            prvt = jose_jwk_from_key(key);
            jose_key_free(key);
            assert(prvt);
            break;
        }

        case TYPE_RSA: {
            RSA *key = NULL;

            key = jose_jwk_to_rsa(kxtra);
            assert(key);

            prvt = jose_jwk_from_rsa(key);
            RSA_free(key);
            assert(prvt);
            break;
        }

        case TYPE_EC: {
            EC_KEY *key = NULL;

            key = jose_jwk_to_ec(kxtra);
            assert(key);

            prvt = jose_jwk_from_ec(key);
            EC_KEY_free(key);
            assert(prvt);
            break;
        }

        default:
            goto next;
        }

        cprvt = jose_jwk_copy(prvt, true);
        cbase = jose_jwk_copy(prvt, false);
        assert(cprvt);
        assert(cbase);

        assert(!json_equal(prvt, kxtra));
        assert(json_equal(prvt, kprvt));
        assert(json_equal(prvt, kbase) == !vectors[i].prvt[0].key);

        assert(!json_equal(cprvt, kxtra));
        assert(json_equal(cprvt, kprvt));
        assert(json_equal(cprvt, kbase) == !vectors[i].prvt[0].key);

        assert(!json_equal(cbase, kxtra));
        assert(!json_equal(cbase, kprvt) == !!vectors[i].prvt[0].key);
        assert(json_equal(cbase, kbase));

        json_decref(prvt);
        json_decref(cprvt);
        json_decref(cbase);

next:
        json_decref(kbase);
        json_decref(kprvt);
        json_decref(kxtra);
    }

    return 0;
}
