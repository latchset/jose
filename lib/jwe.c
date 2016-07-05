/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "misc.h"

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <string.h>

static jose_jwe_crypter_t *crypters;
static jose_jwe_sealer_t *sealers;
static jose_jwe_zipper_t *zippers;

static const jose_jwe_crypter_t *
find_crypter(const char *enc)
{
    for (const jose_jwe_crypter_t *c = crypters; c && enc; c = c->next) {
        for (size_t i = 0; c->encs[i]; i++) {
            if (strcmp(enc, c->encs[i]) == 0)
                return c;
        }
    }

    return NULL;
}

static const jose_jwe_sealer_t *
find_sealer(const char *alg)
{
    for (const jose_jwe_sealer_t *s = sealers; s && alg; s = s->next) {
        for (size_t i = 0; s->algs[i]; i++) {
            if (strcmp(alg, s->algs[i]) == 0)
                return s;
        }
    }

    return NULL;
}

static const jose_jwe_zipper_t *
find_zipper(const char *zip)
{
    for (const jose_jwe_zipper_t *z = zippers; z && zip; z = z->next) {
        if (strcmp(zip, z->zip) == 0)
            return z;
    }

    return NULL;
}

void
jose_jwe_register_crypter(jose_jwe_crypter_t *crypter)
{
    crypter->next = crypters;
    crypters = crypter;
}

void
jose_jwe_register_sealer(jose_jwe_sealer_t *sealer)
{
    sealer->next = sealers;
    sealers = sealer;
}

void
jose_jwe_register_zipper(jose_jwe_zipper_t *zipper)
{
    zipper->next = zippers;
    zippers = zipper;
}

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
    const jose_jwe_crypter_t *crypter = NULL;
    const jose_jwe_zipper_t *zipper = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *penc = NULL;
    const char *senc = NULL;
    const char *zip = NULL;
    const char *aad = NULL;
    uint8_t *zpt = NULL;
    json_t *p = NULL;
    bool ret = false;

    if (!jose_jwk_allowed(cek, "enc", "encrypt"))
        return false;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return false;

    if (json_unpack(jwe, "{s?s,s?{s?s,s?s},s?O,s?{s?s}}", "aad", &aad,
                    "protected", "enc", &penc, "zip", &zip, "protected", &p,
                    "unprotected", "enc", &senc) == -1)
        return false;

    if (!penc && !zip && json_is_string(p)) {
        json_decref(p);
        p = jose_b64_decode_json_load(p);
        if (!p)
            goto egress;

        if (json_unpack(p, "{s?s,s?s}", "enc", &penc, "zip", &zip) == -1)
            goto egress;
    }

    if (penc && senc && strcmp(penc, senc) != 0)
        goto egress;

    if (!penc && !senc) {
        senc = kalg;

        for (crypter = crypters; crypter && !senc; crypter = crypter->next)
            senc = crypter->suggest(cek);

        if (!senc || !set_protected_new(jwe, "enc", json_string(senc)))
            goto egress;
    }

    if (kalg && strcmp(penc ? penc : senc, kalg) != 0)
        goto egress;

    if (zip) {
        zipper = find_zipper(zip);
        if (!zipper)
            goto egress;

        pt = zpt = zipper->deflate(pt, ptl, &ptl);
        if (!zpt)
            goto egress;
    }

    crypter = find_crypter(penc ? penc : senc);
    if (!crypter)
        goto egress;

    prot = encode_protected(jwe);
    if (!prot)
        goto egress;

    ret = crypter->encrypt(jwe, cek, penc ? penc : senc, prot, aad, pt, ptl);

egress:
    json_decref(p);
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
    const jose_jwe_sealer_t *sealer = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    json_t *jh = NULL;
    bool ret = false;

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        return false;

    if (json_unpack(jh, "{s?s}", "alg", &halg) == -1)
        goto egress;

    if (halg && strcmp(halg, "dir") == 0) {
        ret = json_object_size(rcp) == 0;
        json_decref(rcp);
        json_decref(jh);
        return ret;
    }

    if (!jose_jwk_allowed(cek, "enc", "encrypt"))
        goto egress;

    if (!jose_jwk_allowed(jwk, "enc", "wrapKey"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (!rcp)
        rcp = json_object();
    else if (!json_is_object(rcp))
        goto egress;

    if (!halg) {
        json_t *h = NULL;

        halg = kalg;
        for (const jose_jwe_sealer_t *s = sealers; s && !halg; s = s->next)
            halg = s->suggest(jwk);

        if (!halg)
            goto egress;

        h = json_object_get(rcp, "header");
        if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
            goto egress;

        if (json_object_set_new(h, "alg", json_string(halg)) == -1)
            goto egress;
    }

    sealer = find_sealer(halg);
    if (!sealer)
        goto egress;

    if (!sealer->seal(jwe, rcp, jwk, halg, cek))
        goto egress;

    ret = add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);

egress:
    json_decref(rcp);
    json_decref(jh);
    return ret;
}

static json_t *
unseal_rcp(const json_t *jwe, const json_t *rcp, const json_t *jwk)
{
    const jose_jwe_sealer_t *sealer = NULL;
    const char *halg = NULL;
    const char *kalg = NULL;
    json_t *cek = NULL;
    json_t *jh = NULL;

    jh = jose_jwe_merge_header(jwe, rcp);
    if (!jh)
        goto egress;

    if (json_unpack(jh, "{s?s}", "alg", &halg) == -1)
        goto egress;

    if (halg && strcmp(halg, "dir") == 0) {
        json_decref(jh);
        return json_deep_copy(jwk);
    }

    if (!jose_jwk_allowed(jwk, "enc", "unwrapKey"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (halg && kalg && strcmp(halg, kalg) != 0)
        goto egress;

    sealer = find_sealer(halg);
    if (!sealer)
        goto egress;

    cek = json_pack("{s:s,s:s,s:O,s:[ss]}",
                    "kty", "oct", "use", "enc",
                    "enc", json_object_get(jh, "enc"),
                    "key_ops", "encrypt", "decrypt");
    if (!cek)
        goto egress;

    if (!sealer->unseal(jwe, rcp, jwk, halg, cek)) {
        json_decref(jh);
        json_decref(cek);
        return NULL;
    }

egress:
    json_decref(jh);
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
    const jose_jwe_crypter_t *crypter = NULL;
    const jose_jwe_zipper_t *zipper = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *szip = NULL;
    const char *enc = NULL;
    const char *aad = NULL;
    const char *zip = NULL;
    uint8_t *pt = NULL;
    json_t *jh = NULL;

    if (!jose_jwk_allowed(cek, "enc", "decrypt"))
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return NULL;

    if (json_unpack((json_t *) jwe, "{s?s,s?s,s?{s?s}}",
                    "aad", &aad, "protected", &prot,
                    "unprotected", "zip", &szip) == -1)
        return NULL;

    jh = jose_jwe_merge_header(jwe, NULL);
    if (!jh)
        goto egress;

    if (json_unpack(jh, "{s?s,s?s}", "enc", &enc, "zip", &zip) == -1)
        goto egress;

    if (!enc)
        enc = kalg;

    if (kalg) {
        if (strcmp(enc, kalg) != 0)
            goto egress;
    }

    zipper = find_zipper(zip);
    if (zip && (!zipper || szip))
        goto egress;

    crypter = find_crypter(enc);
    if (!crypter)
        goto egress;

    pt = crypter->decrypt(jwe, cek, enc, prot ? prot : "", aad, ptl);

    if (zipper) {
        uint8_t *tmp = NULL;
        tmp = zipper->inflate(pt, *ptl, ptl);
        free(pt);
        pt = tmp;
    }

egress:
    json_decref(jh);
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

json_t *
jose_jwe_merge_header(const json_t *jwe, const json_t *rcp)
{
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;

    p = json_object_get(jwe, "protected");
    if (!p)
        p = json_object();
    else if (json_is_object(p))
        p = json_deep_copy(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);

    if (!json_is_object(p)) {
        json_decref(p);
        return NULL;
    }

    s = json_object_get(jwe, "unprotected");
    if (s) {
        if (json_object_update_missing(p, s) == -1) {
            json_decref(p);
            return NULL;
        }
    }

    h = json_object_get(rcp, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1) {
            json_decref(p);
            return NULL;
        }
    }

    return p;
}
