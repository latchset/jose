/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "bin.h"

#include <assert.h>
#include <string.h>

struct {
    const char *dec;
    const char *enc;
} vectors[] = {
    { "", "" },
    { "f", "Zg==" },
    { "fo", "Zm8=" },
    { "foo", "Zm9v" },
    { "foob", "Zm9vYg==" },
    { "fooba", "Zm9vYmE=" },
    { "foobar", "Zm9vYmFy" },
    {}
};

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].dec; i++) {
        struct bin *bin = NULL;
        json_t *json = NULL;

        bin = bin_new(strlen(vectors[i].dec));
        assert(bin);

        memcpy(bin->buf, vectors[i].dec, strlen(vectors[i].dec));

        json = bin_to_json(bin);
        assert(json);
        assert(json_is_string(json));
        fprintf(stderr, "%s == %s\n", json_string_value(json), vectors[i].enc);
        assert(strcmp(json_string_value(json), vectors[i].enc) == 0);

        bin_free(bin);

        bin = bin_from_json(json);
        json_decref(json);
        assert(bin);
        assert(bin->len == strlen(vectors[i].dec));
        assert(strncmp((char *) bin->buf, vectors[i].dec, bin->len) == 0);

        bin_free(bin);
    }

    return 0;
}
