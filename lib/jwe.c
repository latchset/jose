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

static json_t *
head_merge(const json_t *prot, const json_t *shrd, const json_t *head)
{
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;
    json_t *d = NULL;
    json_t *a = NULL;

    if (json_is_string(prot)) {
        prot = d = jose_b64_decode_json_load(prot);
        if (!d)
            goto error;
    }

    if (prot && !json_is_object(prot))
        goto error;

    if (shrd && !json_is_object(shrd))
        goto error;

    if (head && !json_is_object(head))
        goto error;

    p = json_deep_copy(prot);
    if (prot && !p)
        goto error;

    s = json_deep_copy(shrd);
    if (shrd && !s)
        goto error;

    h = json_deep_copy(head);
    if (head && !h)
        goto error;

    a = json_object();
    if (!a)
        goto error;

    if (p && json_object_update_missing(a, p) == -1)
        goto error;

    if (s && json_object_update_missing(a, s) == -1)
        goto error;

    if (h && json_object_update_missing(a, h) == -1)
        goto error;

    json_decref(p);
    json_decref(s);
    json_decref(h);
    json_decref(d);
    return a;

error:
    json_decref(p);
    json_decref(s);
    json_decref(h);
    json_decref(d);
    json_decref(a);
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
    json_t *hd = NULL;
    bool ret = false;

    hd = head_merge(json_object_get(jwe, "protected"),
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
    json_decref(hd);
    return ret;
}

static json_t *
unseal_rcp(const json_t *jwe, const json_t *rcp, const json_t *jwk)
{
    const jose_jwe_sealer_t *sealer = NULL;
    const char *halg = NULL;
    const char *kalg = NULL;
    json_t *head = NULL;
    json_t *cek = NULL;

    head = head_merge(json_object_get(jwe, "protected"),
                      json_object_get(jwe, "unprotected"),
                      json_object_get(rcp, "header"));
    if (!head)
        goto egress;

    if (json_unpack(head, "{s?s}", "alg", &halg) == -1)
        goto egress;

    if (halg && strcmp(halg, "dir") == 0) {
        json_decref(head);
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
                    "enc", json_object_get(head, "enc"),
                    "key_ops", "encrypt", "decrypt");
    if (!cek)
        goto egress;

    if (!sealer->unseal(jwe, rcp, jwk, halg, cek)) {
        json_decref(head);
        json_decref(cek);
        return NULL;
    }

egress:
    json_decref(head);
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
    const char *senc = NULL;
    const char *penc = NULL;
    const char *aad = NULL;
    const char *zip = NULL;
    uint8_t *pt = NULL;
    json_t *p = NULL;

    if (!jose_jwk_allowed(cek, "enc", "decrypt"))
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) == -1)
        return NULL;

    if (json_unpack((json_t *) jwe, "{s?s,s?s,s?o,s?{s?s}}",
                    "aad", &aad, "protected", &prot, "protected", &p,
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

    zipper = find_zipper(zip);
    if (zip && !zipper)
        goto egress;

    crypter = find_crypter(penc ? penc : senc);
    if (!crypter)
        goto egress;

    pt = crypter->decrypt(jwe, cek, penc ? penc : senc,
                          prot ? prot : "", aad, ptl);

    if (zipper) {
        uint8_t *tmp = NULL;
        tmp = zipper->inflate(pt, *ptl, ptl);
        free(pt);
        pt = tmp;
    }

egress:
    json_decref(p);
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
