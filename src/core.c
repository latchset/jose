/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "core.h"

#include <stdarg.h>
#include <string.h>

size_t
core_str2enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
}
