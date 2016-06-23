/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include "aescbch.h"
#include "aesgcm.h"

#include "rsaes.h"
#include "aeskw.h"

#include <openssl/rand.h>

#include <string.h>

json_t *
jose_jwe_from_compact(const char *jwe)
{
    return compact_to_obj(jwe, "protected", "encrypted_key",
                          "iv", "ciphertext", "tag", NULL);
}

char *
jose_jwe_to_compact(const json_t *jwe)
{
    const char *encrypted_key = NULL;
    const char *unprotected = NULL;
    const char *ciphertext = NULL;
    const char *protected = NULL;
    const char *header = NULL;
    const char *aad = NULL;
    const char *tag = NULL;
    const char *iv = NULL;
    char *out = NULL;

    if (json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:s,s?s,s?s,s?s}",
                    "encrypted_key", &encrypted_key,
                    "ciphertext", &ciphertext,
                    "protected", &protected,
                    "tag", &tag,
                    "iv", &iv,
                    "unprotected", &unprotected,
                    "header", &header,
                    "aad", &aad) == -1 &&
        json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:[{s:s,s?s}!],s?s,s?s}",
                    "ciphertext", &ciphertext,
                    "protected", &protected,
                    "tag", &tag,
                    "iv", &iv,
                    "recipients",
                    "encrypted_key", &encrypted_key,
                    "header", &header,
                    "unprotected", &unprotected,
                    "aad", &aad) == -1)
        return NULL;

    if (unprotected || header || aad)
        return NULL;

    asprintf(&out, "%s.%s.%s.%s.%s",
             protected, encrypted_key, iv, ciphertext, tag);

    return out;
}

EVP_PKEY *
jose_jwe_generate_cek(json_t *jwe)
{
    const char *enc = NULL;
    json_t *header = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *buf = NULL;
    size_t len = 0;

    header = merge_header(json_object_get(jwe, "protected"),
                          json_object_get(jwe, "unprotected"), NULL);
    if (!header)
        goto egress;

    if (json_unpack(header, "{s:s}", "enc", &enc) == -1) {
        enc = "A128CBC-HS256";
        if (!set_protected_new(jwe, "enc", json_string(enc)))
            goto egress;
    }

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
    case 3: len = 32; break;
    case 4: len = 48; break;
    case 5: len = 64; break;
    default: goto egress;
    }

    buf = malloc(len);
    if (!buf)
        goto egress;

    if (RAND_bytes(buf, len) <= 0)
        goto egress;

    key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf, len);

egress:
    json_decref(header);
    free(buf);
    return key;
}

static char *
choose_enc(json_t *jwe, EVP_PKEY *cek)
{
    const char *enc = NULL;
    json_t *header = NULL;
    size_t len = 0;

    if (!cek)
        return NULL;

    if (EVP_PKEY_base_id(cek) != EVP_PKEY_HMAC)
        return NULL;

    if (!EVP_PKEY_get0_hmac(cek, &len))
        return NULL;

    header = merge_header(json_object_get(jwe, "protected"),
                          json_object_get(jwe, "unprotected"), NULL);
    if (!header)
        goto error;

    if (json_unpack(header, "{s:s}", "enc", &enc) == -1) {
        switch (len) {
        case 16: enc = "A128GCM"; break;
        case 24: enc = "A192GCM"; break;
        case 32: enc = "A128CBC-HS256"; break; /* Prefer A128CBC-HS256 */
        case 48: enc = "A192CBC-HS384"; break;
        case 64: enc = "A256CBC-HS512"; break;
        default: goto error;
        }

        if (!set_protected_new(jwe, "enc", json_string(enc)))
            goto error;
    }

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: if (len != 16) goto error; break;
    case 1: if (len != 24) goto error; break;
    case 2: if (len != 32) goto error; break;
    case 3: if (len != 32) goto error; break;
    case 4: if (len != 48) goto error; break;
    case 5: if (len != 64) goto error; break;
    default: goto error;
    }

    enc = strdup(enc);
    json_decref(header);
    return (char *) enc;

error:
    json_decref(header);
    return NULL;
}

bool
jose_jwe_encrypt(json_t *jwe, EVP_PKEY *cek, const uint8_t pt[], size_t ptl)
{
    typeof(&aesgcm_encrypt) encryptor;
    uint8_t *ivcttag = NULL;
    const char *aad = NULL;
    json_t *tmp = NULL;
    json_t *p = NULL;
    bool ret = false;
    char *enc = NULL;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (json_unpack(jwe, "{s?s}", "aad", &aad) == -1)
        goto egress;

    enc = choose_enc(jwe, cek);
    if (!enc)
        goto egress;

    p = encode_protected(jwe);
    if (!p)
        goto egress;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "Ai192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: encryptor = aesgcm_encrypt; break;
    case 1: encryptor = aesgcm_encrypt; break;
    case 2: encryptor = aesgcm_encrypt; break;
    case 3: encryptor = aescbch_encrypt; break;
    case 4: encryptor = aescbch_encrypt; break;
    case 5: encryptor = aescbch_encrypt; break;
    default: goto egress;
    }

    ivcttag = encryptor(enc, cek, pt, ptl, &ivl, &ctl, &tgl,
                        json_string_value(p), aad ? "." : NULL,
                        aad ? aad : "", NULL);
    if (!ivcttag)
        goto egress;

    if (ivl > 0) {
        tmp = jose_b64_encode_json(ivcttag, ivl);
        if (json_object_set_new(jwe, "iv", tmp) == -1)
            goto egress;
    }

    tmp = jose_b64_encode_json(&ivcttag[ivl], ctl);
    if (json_object_set_new(jwe, "ciphertext", tmp) == -1)
        goto egress;

    if (tgl > 0) {
        tmp = jose_b64_encode_json(&ivcttag[ivl + ctl], tgl);
        if (json_object_set_new(jwe, "tag", tmp) == -1)
            goto egress;
    }

    ret = true;

egress:
    free(ivcttag);
    free(enc);
    return ret;
}

bool
jose_jwe_encrypt_json(json_t *jwe, EVP_PKEY *cek, const json_t *pt)
{
    char *ept = NULL;
    bool ret = false;

    ept = json_dumps(pt, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
    if (!ept)
        return NULL;

    ret = jose_jwe_encrypt(jwe, cek, (uint8_t *) ept, strlen(ept));
    free(ept);
    return ret;
}

static char *
choose_alg(json_t *jwe, EVP_PKEY *key, json_t *rcp, const char *kalg)
{
    const char *alg = NULL;
    json_t *header = NULL;
    json_t *h = NULL;

    header = merge_header(json_object_get(jwe, "protected"),
                          json_object_get(jwe, "unprotected"), rcp);
    if (!header)
        goto egress;

    if (json_unpack(header, "{s:s}", "alg", &alg) == 0)
        goto egress;

    alg = kalg;
    if (!alg) {
        size_t len = 0;

        switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_HMAC:
            if (!EVP_PKEY_get0_hmac(key, &len))
                goto egress;

            switch (len * 8) {
            case 128: alg = "A128KW"; break;
            case 192: alg = "A192KW"; break;
            case 256: alg = "A256KW"; break;
            default: goto egress;
            }
            break;

        case EVP_PKEY_RSA: alg = "RSA-OAEP"; break;
        default: goto egress;
        }
    }

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1) {
        alg = NULL;
        goto egress;
    }

    if (json_object_set_new(h, "alg", json_string(alg)) == -1)
        alg = NULL;

egress:
    if (alg) {
        if (!kalg || strcmp(kalg, alg) == 0)
            alg = strdup(alg);
        else
            alg = NULL;
    }
    json_decref(header);
    return (char *) alg;
}

static bool
jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp,
         const char *kalg)
{
    typeof(&aeskw_seal) sealer;
    const uint8_t *pt = NULL;
    uint8_t *ivcttg = NULL;
    json_t *tmp = NULL;
    json_t *h = NULL;
    char *alg = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ivl = 0;
    size_t ctl = 0;
    size_t tgl = 0;

    if (!rcp)
        rcp = json_object();

    if (!json_is_object(rcp))
        goto egress;

    alg = choose_alg(jwe, key, rcp, kalg);
    if (!alg)
        goto egress;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "A128GCMKW", "A192GCMKW", "A256GCMKW", NULL)) {
    case 0: sealer = rsaes_seal; break;
    case 1: sealer = rsaes_seal; break;
    case 2: sealer = rsaes_seal; break;
    case 3: sealer = aeskw_seal; break;
    case 4: sealer = aeskw_seal; break;
    case 5: sealer = aeskw_seal; break;
    case 6: sealer = aesgcmkw_seal; break;
    case 7: sealer = aesgcmkw_seal; break;
    case 8: sealer = aesgcmkw_seal; break;
    default: goto egress;
    }

    pt = EVP_PKEY_get0_hmac(cek, &ptl);
    if (!pt)
        goto egress;

    ivcttg = sealer(alg, key, pt, ptl, &ivl, &ctl, &tgl);
    if (!ivcttg)
        goto egress;

    if (ivl > 0 || tgl > 0) {
        h = json_object_get(rcp, "header");
        if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
            goto egress;
        if (!json_is_object(h))
            goto egress;
    }

    if (ivl > 0) {
        tmp = jose_b64_encode_json(ivcttg, ivl);
        if (json_object_set_new(h, "iv", tmp) == -1)
            goto egress;
    }

    tmp = jose_b64_encode_json(&ivcttg[ivl], ctl);
    if (json_object_set_new(rcp, "encrypted_key", tmp) == -1)
        goto egress;

    if (tgl > 0) {
        tmp = jose_b64_encode_json(&ivcttg[ivl + ctl], tgl);
        if (json_object_set_new(h, "tag", tmp) == -1)
            goto egress;
    }

    ret = add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);

egress:
    json_decref(rcp);
    free(ivcttg);
    free(alg);
    return ret;
}

bool
jose_jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp)
{
    return jwe_seal(jwe, cek, key, rcp, NULL);
}

bool
jose_jwe_seal_jwk(json_t *jwe, EVP_PKEY *cek, const json_t *jwk, json_t *rcp)
{
    const char *alg = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;

    if (!jose_jwk_use_allowed(jwk, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "wrapKey"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &alg) == -1)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (key)
        ret = jwe_seal(jwe, cek, key, json_incref(rcp), alg);

egress:
    EVP_PKEY_free(key);
    json_decref(rcp);
    return ret;
}

static uint8_t *
decode(const char *enc, size_t *l)
{
    uint8_t *dec = NULL;

    if (!enc)
        return NULL;

    *l = jose_b64_dlen(strlen(enc));

    dec = malloc(*l);
    if (!dec)
        return NULL;

    if (jose_b64_decode(enc, dec))
        return dec;

    free(dec);
    return NULL;
}

static EVP_PKEY *
unseal_recip(const json_t *jwe, const json_t *rcp, EVP_PKEY *key)
{
    typeof(&aeskw_unseal) unsealer;
    const char *alg = NULL;
    const char *eiv = NULL;
    const char *ect = NULL;
    const char *etg = NULL;
    json_t *header = NULL;
    EVP_PKEY *cek = NULL;
    uint8_t *iv = NULL;
    uint8_t *ct = NULL;
    uint8_t *tg = NULL;
    uint8_t *pt = NULL;
    ssize_t pl = 0;
    size_t ivl = 0;
    size_t ctl = 0;
    size_t tgl = 0;

    header = merge_header(json_object_get(jwe, "protected"),
                          json_object_get(jwe, "unprotected"),
                          json_object_get(rcp, "header"));
    if (!header)
        goto egress;

    if (json_unpack(header, "{s: s, s? s, s? s}",
                    "alg", &alg, "iv", &eiv, "tag", &etg) == -1)
        goto egress;

    if (json_unpack((json_t *) rcp, "{s: s}", "encrypted_key", &ect) == -1)
        goto egress;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW",
                        "A128GCMKW", "A192GCMKW", "A256GCMKW", NULL)) {
    case 0: unsealer = rsaes_unseal; break;
    case 1: unsealer = rsaes_unseal; break;
    case 2: unsealer = rsaes_unseal; break;
    case 3: unsealer = aeskw_unseal; break;
    case 4: unsealer = aeskw_unseal; break;
    case 5: unsealer = aeskw_unseal; break;
    case 6: unsealer = aesgcmkw_unseal; break;
    case 7: unsealer = aesgcmkw_unseal; break;
    case 8: unsealer = aesgcmkw_unseal; break;
    default: return NULL;
    }

    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (!ct || (eiv && !iv) || (etg && !tg))
        goto egress;

    pt = malloc(ctl);
    if (!pt)
        goto egress;

    pl = unsealer(alg, key, iv, ivl, ct, ctl, tg, tgl, pt);
    if (pl >= 0)
        cek = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pt, pl);

egress:
    json_decref(header);
    free(pt);
    free(iv);
    free(ct);
    free(tg);
    return cek;
}

EVP_PKEY *
jose_jwe_unseal(const json_t *jwe, EVP_PKEY *key)
{
    const json_t *rcps = NULL;
    EVP_PKEY *cek = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (json_is_array(rcps)) {
        for (size_t i = 0; i < json_array_size(rcps) && !cek; i++) {
            const json_t *rcp = json_array_get(rcps, i);
            cek = unseal_recip(jwe, rcp, key);
        }
    } else if (!rcps) {
        cek = unseal_recip(jwe, jwe, key);
    }

    return cek;
}

EVP_PKEY *
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwk)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY *cek = NULL;

    key = jose_jwk_to_key(jwk);
    if (!key)
        return NULL;

    cek = jose_jwe_unseal(jwe, key);
    EVP_PKEY_free(key);
    return cek;
}

ssize_t
jose_jwe_decrypt(const json_t *jwe, EVP_PKEY *cek, uint8_t pt[])
{
    typeof(&aesgcm_decrypt) decryptor;
    const json_t *prot = NULL;
    const char *etg = NULL;
    const char *eiv = NULL;
    const char *ect = NULL;
    const char *aad = NULL;
    const char *enc = NULL;
    json_t *header = NULL;
    uint8_t *tg = NULL;
    uint8_t *ct = NULL;
    uint8_t *iv = NULL;
    ssize_t ptl = -1;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (json_unpack((json_t *) jwe, "{ss,s?s,ss,ss}", "ciphertext", &ect,
                    "aad", &aad, "tag", &etg, "iv", &eiv) == -1)
        goto egress;

    prot = json_object_get(jwe, "protected");
    header = merge_header(prot, json_object_get(jwe, "unprotected"), NULL);
    if (!header)
        goto egress;

    if (json_unpack(header, "{s:s}", "enc", &enc) == -1)
        goto egress;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: decryptor = aesgcm_decrypt; break;
    case 1: decryptor = aesgcm_decrypt; break;
    case 2: decryptor = aesgcm_decrypt; break;
    case 3: decryptor = aescbch_decrypt; break;
    case 4: decryptor = aescbch_decrypt; break;
    case 5: decryptor = aescbch_decrypt; break;
    default: goto egress;
    }

    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (iv && ct && tg) {
        ptl = decryptor(enc, cek, iv, ivl, ct, ctl, tg, tgl, pt,
                        json_is_string(prot) ? json_string_value(prot) : "",
                        aad ? "." : NULL, aad ? aad : "", NULL);
    }

egress:
    json_decref(header);
    free(tg);
    free(ct);
    free(iv);
    return ptl;
}

json_t *
jose_jwe_decrypt_json(const json_t *jwe, EVP_PKEY *cek)
{
    json_t *json = NULL;
    uint8_t *pt = NULL;
    json_t *ct = NULL;
    ssize_t ptl = -1;

    ct = json_object_get(jwe, "ciphertext");
    if (!json_is_string(ct))
        return NULL;

    pt = malloc(jose_b64_dlen(json_string_length(ct)));
    if (pt) {
        ptl = jose_jwe_decrypt(jwe, cek, pt);
        if (ptl >= 0)
            json = json_loadb((char *) pt, ptl, JSON_DECODE_ANY, NULL);
        free(pt);
    }

    return json;
}
