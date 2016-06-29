/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "hook.h"
#include "conv.h"

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

bool
jose_jwe_encrypt(json_t *jwe, const json_t *cek,
                 const uint8_t pt[], size_t ptl)
{
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *penc = NULL;
    const char *senc = NULL;
    const char *zip = NULL;
    const char *aad = NULL;
    uint8_t *ivcttg = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *zpt = NULL;
    json_t *tmp = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (!jose_jwk_use_allowed(cek, "enc"))
        return false;

    if (!jose_jwk_op_allowed(cek, "encrypt"))
        return false;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return false;

    if (json_unpack(jwe, "{s?o,s?s,s?{s?s}}", "protected", &p,
                    "aad", &aad, "unprotected", "enc", &senc) == -1)
        return false;

    if (json_is_string(p))
        p = jose_b64_decode_json_load(p);
    else if (json_is_object(p))
        p = json_incref(p);
    else if (p)
        return false;

    if (p && json_unpack(p, "{s?s,s?s}", "enc", &penc, "zip", &zip) == -1)
        goto egress;

    if (penc && senc && strcmp(penc, senc) != 0)
        goto egress;

    if (!penc && !senc) {
        penc = kalg;

        for (const algo_t *a = algos; a && !penc; a = a->next) {
            if (a->type != ALGO_TYPE_CRYPT || !a->suggest)
                continue;

            penc = a->suggest(cek);
        }

        if (!penc || !set_protected_new(jwe, "enc", json_string(penc)))
            goto egress;
    }

    if (kalg && strcmp(penc ? penc : senc, kalg) != 0)
        goto egress;

    prot = encode_protected(jwe);
    if (!prot)
        goto egress;

    key = jose_jwk_to_key(cek);
    if (!key)
        goto egress;

    for (const comp_t *c = comps; c && zip; c = c->next) {
        if (strcmp(c->name, zip) == 0) {
            pt = zpt = c->deflate(pt, ptl, &ptl);
            if (!zpt)
                goto egress;
            break;
        }
    }

    for (const algo_t *a = algos; a && !ivcttg; a = a->next) {
        if (a->type != ALGO_TYPE_CRYPT || !a->encrypt)
            continue;

        for (size_t i = 0; a->names[i] && !ivcttg; i++) {
            if (strcmp(penc ? penc : senc, a->names[i]) != 0)
                continue;

            ivcttg = a->encrypt(penc ? penc : senc, key, pt, ptl,
                                &ivl, &ctl, &tgl, prot,
                                aad ? "." : NULL,
                                aad ? aad : "", NULL);
        }
    }
    if (!ivcttg)
        goto egress;

    if (ivl > 0) {
        tmp = jose_b64_encode_json(ivcttg, ivl);
        if (json_object_set_new(jwe, "iv", tmp) == -1)
            goto egress;
    }

    tmp = jose_b64_encode_json(&ivcttg[ivl], ctl);
    if (json_object_set_new(jwe, "ciphertext", tmp) == -1)
        goto egress;

    if (tgl > 0) {
        tmp = jose_b64_encode_json(&ivcttg[ivl + ctl], tgl);
        if (json_object_set_new(jwe, "tag", tmp) == -1)
            goto egress;
    }

    ret = true;

egress:
    EVP_PKEY_free(key);
    json_decref(p);
    free(ivcttg);
    free(zpt);
    return ret;
}

bool
jose_jwe_encrypt_json(json_t *jwe, const json_t *cek, json_t *pt)
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

bool
jose_jwe_seal(json_t *jwe, const json_t *cek, const json_t *jwk, json_t *rcp)
{
    const char *kalg = NULL;
    const char *halg = NULL;
    const char *ckty = NULL;
    const char *ck = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *ict = NULL;
    uint8_t *pt = NULL;
    json_t *tmp = NULL;
    json_t *hd = NULL;
    json_t *h = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ivl = 0;
    size_t ctl = 0;
    size_t tgl = 0;

    hd = merge_header(json_object_get(jwe, "protected"),
                      json_object_get(jwe, "unprotected"),
                      json_object_get(rcp, "header"));
    if (!hd)
        goto egress;

    if (json_unpack(hd, "{s?s}", "alg", &halg) == -1)
        goto egress;

    if (halg && strcmp(halg, "dir") == 0) {
        ret = json_object_size(rcp) == 0;
        json_decref(rcp);
        json_decref(hd);
        return ret;
    }

    if (!jose_jwk_use_allowed(cek, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(cek, "encrypt"))
        goto egress;

    if (!jose_jwk_use_allowed(jwk, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "wrapKey"))
        goto egress;

    if (json_unpack((json_t *) cek, "{s:s,s:s}", "kty", &ckty, "k", &ck) == -1)
        goto egress;

    if (strcmp(ckty, "oct") != 0)
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (!rcp)
        rcp = json_object();
    else if (!json_is_object(rcp))
        goto egress;

    if (!halg) {
        halg = kalg;

        for (const algo_t *a = algos; a && !halg; a = a->next) {
            if (a->type != ALGO_TYPE_SEAL || !a->suggest)
                continue;

            halg = a->suggest(jwk);
        }

        if (!halg)
            goto egress;

        h = json_object_get(rcp, "header");
        if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
            goto egress;

        if (json_object_set_new(h, "alg", json_string(halg)) == -1)
            goto egress;
    }

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    ptl = jose_b64_dlen(strlen(ck));
    pt = malloc(ptl);
    if (!pt)
        goto egress;

    if (!jose_b64_decode(ck, pt))
        goto egress;

    for (const algo_t *a = algos; a && !ict; a = a->next) {
        if (a->type != ALGO_TYPE_SEAL || !a->seal)
            continue;

        for (size_t i = 0; a->names[i] && !ict; i++) {
            if (strcmp(halg, a->names[i]) != 0)
                continue;

            ict = a->seal(halg, key, pt, ptl, &ivl, &ctl, &tgl);
        }
    }
    if (!ict)
        goto egress;

    if (ivl > 0 || tgl > 0) {
        h = json_object_get(rcp, "header");
        if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
            goto egress;
        if (!json_is_object(h))
            goto egress;
    }

    if (ivl > 0) {
        tmp = jose_b64_encode_json(ict, ivl);
        if (json_object_set_new(h, "iv", tmp) == -1)
            goto egress;
    }

    tmp = jose_b64_encode_json(&ict[ivl], ctl);
    if (json_object_set_new(rcp, "encrypted_key", tmp) == -1)
        goto egress;

    if (tgl > 0) {
        tmp = jose_b64_encode_json(&ict[ivl + ctl], tgl);
        if (json_object_set_new(h, "tag", tmp) == -1)
            goto egress;
    }

    ret = add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);

egress:
    EVP_PKEY_free(key);
    json_decref(rcp);
    json_decref(hd);
    free(ict);
    free(pt);
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

static json_t *
unseal_rcp(const json_t *jwe, const json_t *rcp, const json_t *jwk)
{
    const char *halg = NULL;
    const char *kalg = NULL;
    const char *eiv = NULL;
    const char *ect = NULL;
    const char *etg = NULL;
    EVP_PKEY *key = NULL;
    json_t *head = NULL;
    json_t *cek = NULL;
    uint8_t *iv = NULL;
    uint8_t *ct = NULL;
    uint8_t *tg = NULL;
    uint8_t *pt = NULL;
    size_t ivl = 0;
    size_t ctl = 0;
    size_t tgl = 0;
    size_t ptl = 0;

    head = merge_header(json_object_get(jwe, "protected"),
                        json_object_get(jwe, "unprotected"),
                        json_object_get(rcp, "header"));
    if (!head)
        goto egress;

    if (json_unpack(head, "{s?s,s?s,s?s}",
                    "alg", &halg, "iv", &eiv, "tag", &etg) == -1)
        goto egress;

    if (halg && strcmp(halg, "dir") == 0) {
        json_decref(head);
        return json_deep_copy(jwk);
    }

    if (!jose_jwk_use_allowed(jwk, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "unwrapKey"))
        goto egress;

    if (json_unpack((json_t *) rcp, "{s:s}", "encrypted_key", &ect) == -1)
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (halg && kalg && strcmp(halg, kalg) != 0)
        goto egress;

    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (!ct || (eiv && !iv) || (etg && !tg))
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    for (const algo_t *a = algos; a && !pt; a = a->next) {
        if (a->type != ALGO_TYPE_SEAL || !a->unseal)
            continue;

        for (size_t i = 0; a->names[i] && !pt; i++) {
            if (strcmp(halg ? halg : kalg, a->names[i]) != 0)
                continue;

            pt = a->unseal(halg ? halg : kalg, key,
                           iv, ivl, ct, ctl, tg, tgl, &ptl);
        }
    }
    if (!pt)
        goto egress;

    cek = json_pack("{s:s,s:s,s:o,s:O,s:[ss]}",
                    "kty", "oct", "use", "oct",
                    "k", jose_b64_encode_json(pt, ptl),
                    "enc", json_object_get(head, "enc"),
                    "key_ops", "encrypt", "decrypt");

egress:
    EVP_PKEY_free(key);
    json_decref(head);
    free(pt);
    free(iv);
    free(ct);
    free(tg);
    return cek;
}

json_t *
jose_jwe_unseal(const json_t *jwe, const json_t *jwk)
{
    const json_t *rcps = NULL;
    json_t *cek = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (json_is_array(rcps)) {
        for (size_t i = 0; i < json_array_size(rcps) && !cek; i++) {
            const json_t *rcp = json_array_get(rcps, i);
            cek = unseal_rcp(jwe, rcp, jwk);
        }
    } else if (!rcps) {
        cek = unseal_rcp(jwe, jwe, jwk);
    }

    return cek;
}

uint8_t *
jose_jwe_decrypt(const json_t *jwe, const json_t *cek, size_t *ptl)
{
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *senc = NULL;
    const char *penc = NULL;
    const char *etg = NULL;
    const char *eiv = NULL;
    const char *ect = NULL;
    const char *aad = NULL;
    const char *zip = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *tg = NULL;
    uint8_t *ct = NULL;
    uint8_t *iv = NULL;
    uint8_t *pt = NULL;
    json_t *p = NULL;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (!jose_jwk_use_allowed(cek, "enc"))
        return NULL;

    if (!jose_jwk_op_allowed(cek, "decrypt"))
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return NULL;

    if (json_unpack((json_t *) jwe, "{s:s,s?s,s:s,s:s,s?s,s?o,s?{s?s}}",
                    "ciphertext", &ect, "aad", &aad, "tag", &etg, "iv", &eiv,
                    "protected", &prot, "protected", &p,
                    "unprotected", "enc", &senc) == -1)
        return NULL;

    if (json_is_string(p))
        p = jose_b64_decode_json_load(p);
    else if (p)
        return NULL;

    if (p && json_unpack(p, "{s?s,s?s}", "enc", &penc, "zip", &zip) == -1)
        goto egress;

    if (!penc && !senc) {
        if (!kalg)
            goto egress;
        senc = kalg;
    }

    if (kalg) {
        if (penc && strcmp(penc, kalg) != 0)
            goto egress;
        if (senc && strcmp(senc, kalg) != 0)
            goto egress;
    }

    key = jose_jwk_to_key(cek);
    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (!key || !iv || !ct || !tg)
        goto egress;

    for (const algo_t *a = algos; a && !pt; a = a->next) {
        if (a->type != ALGO_TYPE_CRYPT || !a->decrypt)
            continue;

        for (size_t i = 0; a->names[i] && !pt; i++) {
            if (strcmp(penc ? penc : senc, a->names[i]) != 0)
                continue;

            pt = a->decrypt(penc ? penc : senc, key,
                            iv, ivl, ct, ctl, tg, tgl, ptl,
                            prot ? prot : "",
                            aad ? "." : NULL,
                            aad ? aad : "", NULL);
        }
    }

    for (const comp_t *c = comps; c && pt && zip; c = c->next) {
        if (strcmp(zip, c->name) == 0) {
            uint8_t *tmp = NULL;

            tmp = c->inflate(pt, *ptl, ptl);
            free(pt);
            pt = tmp;
            if (!tmp)
                goto egress;
            break;
        }
    }

egress:
    EVP_PKEY_free(key);
    json_decref(p);
    free(tg);
    free(ct);
    free(iv);
    return pt;
}

json_t *
jose_jwe_decrypt_json(const json_t *jwe, const json_t *cek)
{
    json_t *json = NULL;
    uint8_t *pt = NULL;
    json_t *ct = NULL;
    size_t ptl = 0;

    ct = json_object_get(jwe, "ciphertext");
    if (!json_is_string(ct))
        return NULL;

    pt = jose_jwe_decrypt(jwe, cek, &ptl);
    if (pt) {
        json = json_loadb((char *) pt, ptl, JSON_DECODE_ANY, NULL);
        free(pt);
    }

    return json;
}
