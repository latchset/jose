/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "b64.h"

#include <assert.h>
#include <string.h>

struct {
    const char *dec;
    const char *enc;
} vectors[] = {
    { "", "" },
    { "f", "Zg" },
    { "fo", "Zm8" },
    { "foo", "Zm9v" },
    { "foob", "Zm9vYg" },
    { "fooba", "Zm9vYmE" },
    { "foobar", "Zm9vYmFy" },
    { "\xc7\xf1\x44\xcd\x1b\xbd\x9b~\x87,\xdf\xed", "x_FEzRu9m36HLN_t" },
    {}
};

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].dec; i++) {
        uint8_t *buf = NULL;
        json_t *json = NULL;
        size_t len = 0;

        json = jose_b64_encode((uint8_t *) vectors[i].dec,
                               strlen(vectors[i].dec));
        assert(json_is_string(json));
        assert(strcmp(json_string_value(json), vectors[i].enc) == 0);

        buf = jose_b64_decode(json, &len);
        json_decref(json);
        assert(buf);
        assert(len == strlen(vectors[i].dec));
        assert(strncmp((char *) buf, vectors[i].dec, len) == 0);
        free(buf);
    }

    return 0;
}
