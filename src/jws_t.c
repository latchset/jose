/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include "b64.h"
#include "jwkset.h"

#include <openssl/objects.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>

struct kv {
    const char *key;
    const char *val;
};

struct sig {
    const char *prot; /* Base64 URL Encoded */
    const char *sign; /* Base64 URL Encoded */
    struct kv *key;
    bool fixed;       /* Can jose_jws_sign() produce the same signature? */
};

struct example {
    const char *payl; /* Base64 URL Encoded */
    struct sig *sigs;
};

static const struct example RFC7515_A_1 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      (struct kv[]) {
        { "kty", "oct" },
        { "k",   "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKt"
                 "MN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" },
        {},
      }, false },
    {}
  }
};

static const struct example RFC7515_A_2 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJhbGciOiJSUzI1NiJ9",
      "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuH"
      "Im4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdi"
      "uB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN"
      "9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2"
      "w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
      (struct kv[]) {
        { "kty", "RSA" },
        { "n",   "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPdd"
                 "xHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgN"
                 "MsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kp"
                 "aSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xs"
                 "mtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNm"
                 "oudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ" },
        { "e",   "AQAB" },
        { "d",   "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97"
                 "IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1"
                 "O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqz"
                 "jkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4e"
                 "hNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9p"
                 "IuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ" },
        { "p",   "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUd"
                 "iYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmn"
                 "PGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc" },
        { "q",   "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZx"
                 "aewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-Tn"
                 "BA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc" },
        { "dp",  "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                 "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2z"
                 "b34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0" },
        { "dq",  "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                 "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-k"
                 "yNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU" },
        { "qi",  "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                 "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPL"
                 "UW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U" },
        {}
      }, true },
    {},
  }
};

static const struct example RFC7515_A_3 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJhbGciOiJFUzI1NiJ9",
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQ"
      "xfKTUJqPP3-Kg6NU1Q",
      (struct kv[]) {
        { "kty", "EC" },
        { "crv", "P-256" },
        { "x",   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" },
        { "y",   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
        { "d",   "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI" },
        {}
      }, false },
    {}
  }
};

static const struct example RFC7515_A_4 = {
  "UGF5bG9hZA",
  (struct sig[]) {
    { "eyJhbGciOiJFUzUxMiJ9",
      "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2"
      "SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqO"
      "gzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",
      (struct kv[]) {
        { "kty", "EC" },
        { "crv", "P-521" },
        { "x",   "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_N"
                 "jFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk" },
        { "y",   "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly"
                 "79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2" },
        { "d",   "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAx"
                 "erEzgdRhajnu0ferB0d53vM9mE15j2C" },
        {}
      }, false },
    {}
  }
};

static const struct example RFC7515_A_5 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJhbGciOiJub25lIn0", },
    {}
  }
};

static const struct example RFC7515_A_6 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJhbGciOiJSUzI1NiJ9",
      "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuH"
      "Im4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdi"
      "uB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN"
      "9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2"
      "w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
      (struct kv[]) {
        { "kty", "RSA" },
        { "kid", "2010-12-29" },
        { "n",   "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPdd"
                 "xHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgN"
                 "MsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kp"
                 "aSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xs"
                 "mtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNm"
                 "oudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ" },
        { "e",   "AQAB" },
        { "d",   "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97"
                 "IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1"
                 "O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqz"
                 "jkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4e"
                 "hNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9p"
                 "IuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ" },
        { "p",   "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUd"
                 "iYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmn"
                 "PGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc" },
        { "q",   "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZx"
                 "aewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-Tn"
                 "BA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc" },
        { "dp",  "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                 "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2z"
                 "b34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0" },
        { "dq",  "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                 "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-k"
                 "yNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU" },
        { "qi",  "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                 "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPL"
                 "UW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U" },
        {}
      }, true },
    { "eyJhbGciOiJFUzI1NiJ9",
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQ"
      "xfKTUJqPP3-Kg6NU1Q",
      (struct kv[]) {
        { "kty", "EC" },
        { "crv", "P-256" },
        { "kid", "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        { "x",   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" },
        { "y",   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
        { "d",   "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI" },
        {}
      }, false },
    {},
  }
};

static const struct example *examples[] = {
    &RFC7515_A_1,
    &RFC7515_A_2,
    &RFC7515_A_3,
    &RFC7515_A_4,
    &RFC7515_A_5,
    &RFC7515_A_6,
    NULL
};

static json_t *
make_key(struct kv *attrs)
{
    json_t *key = NULL;

    key = json_object();
    if (!key)
        return NULL;

    for (size_t i = 0; attrs && attrs[i].key; i++) {
        int r = 0;

        r = json_object_set_new(key, attrs[i].key, json_string(attrs[i].val));
        if (r == -1) {
            json_decref(key);
            return NULL;
        }
    }

    return key;
}

static void
test_compact_verify(const struct example *e)
{
    json_t *jwk = NULL;
    json_t *jws = NULL;
    char *c = NULL;

    fprintf(stderr, "============= %s\n", __FUNCTION__);

    /* Skip examples without a signature. */
    if (!e->sigs[0].prot)
        return;

    asprintf(&c, "%s.%s.%s", e->sigs[0].prot, e->payl,
             e->sigs[0].sign ? e->sigs[0].sign : "");
    assert(c);

    fprintf(stderr, "%s\n\n", c);

    jws = jose_jws_from_compact(c);
    assert(json_is_object(jws));
    free(c);

    json_dumpf(jws, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n\n");

    jwk = make_key(e->sigs[0].key);
    assert(json_is_object(jwk));

    json_dumpf(jwk, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n\n");

    assert(jose_jws_verify_jwk(jws, jwk, true) == !!e->sigs[0].sign);
    json_decref(jwk);
    json_decref(jws);
}

static void
test_flattened_verify(const struct example *e)
{
    json_t *jwk = NULL;
    json_t *jws = NULL;

    fprintf(stderr, "============= %s\n", __FUNCTION__);

    /* Skip examples without a signature. */
    if (!e->sigs[0].prot)
        return;

    jws = json_pack("{s:s, s:s}",
                    "payload", e->payl,
                    "protected", e->sigs[0].prot);
    assert(json_is_object(jws));

    if (e->sigs[0].sign) {
        assert(json_object_set_new(
            jws, "signature", json_string(e->sigs[0].sign)
        ) == 0);
    }

    json_dumpf(jws, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n\n");

    jwk = make_key(e->sigs[0].key);
    assert(json_is_object(jwk));

    json_dumpf(jwk, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n\n");

    assert(jose_jws_verify_jwk(jws, jwk, true) == !!e->sigs[0].sign);
    json_decref(jwk);
    json_decref(jws);
}

static void
test_general_sign_and_verify(const struct example *e)
{
    json_t *jwkset = NULL;
    json_t *jwks = NULL;
    json_t *jws = NULL;

    fprintf(stderr, "============= %s\n", __FUNCTION__);

    jwks = json_array();
    assert(jwks);

    jws = json_pack("{s: s}", "payload", e->payl);
    assert(jws);

    for (size_t i = 0; e->sigs[i].prot; i++) {
        const json_t *sig = NULL;
        json_t *jwk = NULL;

        /* Skip examples without a key */
        if (!e->sigs[i].key)
            goto egress;

        jwk = make_key(e->sigs[i].key);
        assert(json_is_object(jwk));

        assert(json_array_append_new(jwks, jwk) == 0);

        /* Sign the JWS. */
        assert(jose_jws_sign_jwk_pack(jws, jwk, "K", "{s:s}",
                                      "protected", e->sigs[i].prot));

        json_dumpf(jws, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n\n");

        json_dumpf(jwk, stderr, JSON_SORT_KEYS);
        fprintf(stderr, "\n\n");

        if (e->sigs[i].fixed) {
            /* Check the signature against our expected result. */
            sig = json_object_get(
                i == 0 ? jws : json_array_get(
                    json_object_get(jws, "signatures"), i),
                "signature"
            );
            assert(json_is_string(sig));
            assert(strcmp(
                json_string_value(sig),
                e->sigs[i].sign
            ) == 0);
        }

        /* Check that the signature verifies. */
        assert(jose_jws_verify_jwk(jws, jwk, true));
        assert(jose_jws_verify_jwk(jws, jwks, true));
    }

    jwkset = jose_jwkset_dup(jwks, true);
    assert(jwkset);
    assert(jose_jws_verify_jwk(jws, jwkset, true));

egress:
    json_decref(jwkset);
    json_decref(jwks);
    json_decref(jws);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; examples[i]; i++) {
        fprintf(stderr, "===============================================\n\n");
        test_compact_verify(examples[i]);
        test_flattened_verify(examples[i]);
        test_general_sign_and_verify(examples[i]);
    }

    return 0;
}
