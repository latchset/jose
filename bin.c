/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "bin.h"

#include <stddef.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

struct bin *
bin_new(size_t len)
{
    struct bin *bin = NULL;

    bin = malloc(offsetof(struct bin, buf) + len);
    if (!bin)
        return NULL;

    bin->len = len;
    return bin;
}

void
bin_free(struct bin *bin)
{
    free(bin);
}

struct bin *
bin_from_json(const json_t *json)
{
    struct bin *bin = NULL;
    BIO *mem = NULL;
    BIO *b64 = NULL;
    int len = 0;

    if (!json_is_string(json))
        return NULL;

    bin = bin_new((json_string_length(json) + 3) / 4 * 3);
    if (!bin)
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
        goto error;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new_mem_buf(json_string_value(json), json_string_length(json));
    if (!mem)
        goto error;

    b64 = BIO_push(b64, mem);

    len = BIO_read(b64, bin->buf, bin->len);
    if (len < 0)
        goto error;

    BIO_free_all(b64);
    bin->len = len;
    return bin;

error:
    BIO_free_all(b64);
    bin_free(bin);
    return NULL;
}

json_t *
bin_to_json(const struct bin *bin)
{
    json_t *json = NULL;
    char *buf = NULL;
    BIO *mem = NULL;
    BIO *b64 = NULL;
    long len = 0;

    if (!bin)
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
        goto error;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new(BIO_s_mem());
    if (!mem)
        goto error;

    b64 = BIO_push(b64, mem);

    if (BIO_write(b64, bin->buf, bin->len) != (int) bin->len)
        goto error;

    BIO_flush(b64);

    len = BIO_get_mem_data(mem, &buf);
    if (len < (int) bin->len / 3 * 4)
        goto error;

    if (len == 0)
        json = json_string("");
    else
        json = json_stringn(buf, len);

error:
    BIO_free_all(b64);
    return json;
}

