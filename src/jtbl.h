/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>

typedef struct jtbl_value jtbl_value_t;
typedef struct jtbl_named jtbl_named_t;

struct jtbl_value {
    json_type type;
    union {
        double r;
        json_int_t i;
        const char *s;
        jtbl_value_t *a;
        jtbl_named_t *o;
    };
};

struct jtbl_named {
    const char *k;
    jtbl_value_t v;
};

bool
jtbl_is_end(const jtbl_value_t *val);

json_t *
jtbl_make(const jtbl_value_t *val);
