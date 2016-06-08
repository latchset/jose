#pragma once

#include <openssl/ec.h>
#include <jansson.h>

json_t *
jose_jwk_from_ec_key(const EC_KEY *key, BN_CTX *ctx);

EC_KEY *
jose_jwk_to_ec_key(const json_t *jwk, BN_CTX *ctx);
