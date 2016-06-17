/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "cek.h"

#include <stddef.h>
#include <stdint.h>

struct jose_cek {
    const size_t len;
    uint8_t buf[];
};

jose_cek_t * __attribute__((warn_unused_result))
cek_new(size_t len);
