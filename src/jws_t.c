/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jws.h"
#include "b64.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/objects.h>

struct kv {
    const char *key;
    const char *val;
};

struct sig {
    const char *prot; /* Base64 URL Encoded */
    const char *sign; /* Base64 URL Encoded */
    struct kv *key;
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
      } },
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
      } },
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
      } },
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
      } },
    {}
  }
};

static const struct example RFC7515_A_5 = {
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
  "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  (struct sig[]) {
    { "eyJhbGciOiJub25lIn0", NULL, (struct kv[]) {{}} },
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
      } },
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
      } },
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

    for (size_t i = 0; attrs[i].key; i++) {
        int r = 0;

        r = json_object_set_new(key, attrs[i].key, json_string(attrs[i].val));
        if (r == -1) {
            json_decref(key);
            return NULL;
        }
    }

    return key;
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; examples[i]; i++) {
        json_t *jws = NULL;

        fprintf(stderr, "=================================================\n");

        /* Only test compact mode if we have zero or one signatures. */
        if (!examples[i]->sigs[0].prot || !examples[i]->sigs[1].prot) {
            const char *prot = examples[i]->sigs[0].prot;
            const char *sign = examples[i]->sigs[0].sign;
            const char *payl = examples[i]->payl;
            json_t *jwk = NULL;
            char *c = NULL;

            asprintf(&c, "%s.%s.%s", prot ? prot : "", payl, sign ? sign : "");
            assert(c);

            jws = jose_jws_from_compact(c);
            assert(json_is_object(jws));
            free(c);

            json_dumpf(jws, stderr, JSON_SORT_KEYS);
            fprintf(stderr, "\n");

            jwk = make_key(examples[i]->sigs[0].key);
            assert(json_is_object(jwk));

            assert(jose_jws_verify(jws, jwk, true) == !!sign);
            json_decref(jwk);
            json_decref(jws);
        }

        jws = json_pack("{s: s}", "payload", examples[i]->payl);
        assert(jws);

        for (size_t j = 0; examples[i]->sigs[j].prot; j++) {
            const json_t *sig = NULL;
            json_t *enc = NULL;
            json_t *dec = NULL;
            json_t *key = NULL;
            
            /* Turn the Protected Header into a JSON string. */
            enc = json_string(examples[i]->sigs[j].prot);
            assert(json_is_string(enc));

            /* Decode the Protected Header into a JSON object. */
            dec = jose_b64_decode_json(enc);
            assert(json_is_object(dec));
            json_decref(enc);

            /* Sign the JWS. */
            key = make_key(examples[i]->sigs[j].key);
            assert(key);
            assert(jose_jws_sign(
                jws, NULL, dec, key,
                JOSE_JWS_FLAGS_KID_HEAD
            ));

            json_dumpf(jws, stderr, JSON_SORT_KEYS);
            fprintf(stderr, "\n");

            /* If the Protected Header has more than one attribute,
             * we need to skip static validation. This is because we
             * cannot guarantee ordering of the attributes. */
            if (json_object_size(dec) <= 1) {
                /* Check the signature against our expected result. */
                sig = json_object_get(
                    j == 0 ? jws : json_array_get(
                        json_object_get(jws, "signatures"), j),
                    "signature"
                );
                assert(json_is_string(sig));
                assert(strcmp(
                    json_string_value(sig),
                    examples[i]->sigs[j].sign
                ) == 0);
            }

            /* Check that the signature verifies. */
            assert(jose_jws_verify(jws, key, true));
            json_decref(key);
            json_decref(dec);
        }

        json_decref(jws);
    }

    return 0;
}
