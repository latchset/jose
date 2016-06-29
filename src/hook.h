/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jansson.h>
#include <openssl/evp.h>
#include <stdbool.h>

typedef enum {
    ALGO_TYPE_NONE = 0,
    ALGO_TYPE_CRYPT,
    ALGO_TYPE_SEAL,
    ALGO_TYPE_SIGN
} algo_type_t;

typedef struct algo {
    struct algo *next;

    const char **names;
    algo_type_t type;

    bool
    (*generate)(json_t *jwk);

    const char *
    (*suggest)(const json_t *jwk);

    union {
        struct {
            uint8_t *
            (*encrypt)(const char *alg, EVP_PKEY *key,
                       const uint8_t pt[], size_t ptl,
                       size_t *ivl, size_t *ctl, size_t *tgl, ...);

            uint8_t *
            (*decrypt)(const char *alg, EVP_PKEY *key,
                       const uint8_t iv[], size_t ivl,
                       const uint8_t ct[], size_t ctl,
                       const uint8_t tg[], size_t tgl,
                       size_t *ptl, ...);
        };

        struct {
            uint8_t *
            (*seal)(const char *alg, EVP_PKEY *key,
                    const uint8_t pt[], size_t ptl,
                    size_t *ivl, size_t *ctl, size_t *tgl);

            uint8_t *
            (*unseal)(const char *alg, EVP_PKEY *key,
                      const uint8_t iv[], size_t ivl,
                      const uint8_t ct[], size_t ctl,
                      const uint8_t tg[], size_t tgl,
                      size_t *ptl);
        };

        struct {
            uint8_t *
            (*sign)(const char *alg, EVP_PKEY *key,
                    const char *prot, const char *payl,
                    size_t *sigl);

            bool
            (*verify)(const char *alg, EVP_PKEY *key,
                      const char *prot, const char *payl,
                      const uint8_t sig[], size_t sigl);
        };
    };
} algo_t;

typedef struct comp {
    struct comp *next;
    const char *name;

    uint8_t *(*deflate)(const uint8_t val[], size_t len, size_t *out);
    uint8_t *(*inflate)(const uint8_t val[], size_t len, size_t *out);
} comp_t;

extern algo_t *algos;
extern comp_t *comps;
