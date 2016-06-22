/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <stdbool.h>

#include <openssl/evp.h>

bool
hash(const EVP_MD *md, uint8_t hsh[], ...);
