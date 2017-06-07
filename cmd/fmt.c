/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "jose.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>

#define SUMMARY "Converts JSON between serialization formats"
#define JAIN json_array_insert_new

static const char *prefix = "jose fmt [OPTIONS]\n\n" SUMMARY;

typedef struct {
    json_t *args;
} jcmd_opt_t;

static size_t
convert_int(const json_t *arr, const char *arg)
{
    ssize_t indx = 0;

    if (sscanf(arg, "%zd", &indx) != 1)
        return SIZE_MAX;

    if (indx < 0)
        indx += json_array_size(arr);

    if (indx < 0)
        return SIZE_MAX;

    return indx;
}

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    json_decref(opt->args);
}

static bool
cmd_output(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const int wflags = JSON_ENCODE_ANY | JSON_COMPACT | JSON_SORT_KEYS;
    const char *s = json_string_value(arg);
    FILE *file = NULL;
    bool ret = false;

    if (strcmp(s, "-") == 0)
        file = stdout;
    else
        file = fopen(s, "w");
    if (!file)
        return false;

    if (json_dumpf(cur, file, wflags) < 0)
        goto egress;

    if (isatty(fileno(file)) && fwrite("\n", 1, 1, file) != 1)
        goto egress;

    ret = true;

egress:
    if (strcmp(s, "-") == 0)
        fclose(file);
    return ret;
}

static bool
cmd_foreach(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const int wflags = JSON_ENCODE_ANY | JSON_COMPACT | JSON_SORT_KEYS;
    const char *s = json_string_value(arg);
    FILE *file = NULL;
    bool ret = false;

    if (!json_is_array(cur) && !json_is_object(cur))
        return false;

    if (strcmp(s, "-") == 0)
        file = stdout;
    else
        file = fopen(s, "w");
    if (!file)
        return false;

    if (json_is_array(cur)) {
        json_t *v = NULL;
        size_t i = 0;

        json_array_foreach(cur, i, v) {
            if (json_dumpf(v, file, wflags) < 0 ||
                fprintf(file, "\n") < 0)
                goto egress;
        }
    } else if (json_is_object(cur)) {
        const char *k = NULL;
        json_t *v = NULL;

        json_object_foreach(cur, k, v) {
            if (fprintf(file, "%s=", k) < 0 ||
                json_dumpf(v, file, wflags) < 0 ||
                fprintf(file, "\n") < 0)
                goto egress;
        }
    }

    ret = true;

egress:
    if (strcmp(s, "-") == 0)
        fclose(file);
    return ret;
}

static bool
cmd_unquote(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const char *s = json_string_value(arg);
    FILE *file = NULL;
    bool ret = false;

    if (!json_is_string(cur))
        return false;

    if (strcmp(s, "-") == 0)
        return fprintf(stdout, "%s\n", json_string_value(cur)) >= 0;

    file = fopen(s, "w");
    if (!file)
        return false;

    ret = fprintf(file, "%s\n", json_string_value(cur)) >= 0;
    fclose(file);
    return ret;
}

static bool
cmd_move(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    json_int_t i = json_integer_value(arg);

    if (json_array_insert(stk, i + 1, cur) < 0)
        return false;

    if (json_array_remove(stk, 0) < 0)
        return false;

    return true;
}

static bool
cmd_trunc(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    size_t i = json_integer_value(arg);
    size_t s;

    for (s = json_array_size(cur); s > i; s--) {
        if (json_array_remove(cur, s - 1) < 0)
            return false;
    }

    return true;
}

static bool
cmd_insert(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    size_t i = json_integer_value(arg);
    return json_array_insert(lst, i, cur) >= 0;
}

static bool
cmd_append(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    if (json_is_array(lst))
        return json_array_append(lst, cur) >= 0;

    if (json_is_object(lst))
        return json_object_update_missing(lst, cur) >= 0;

    return false;
}

static bool
cmd_extend(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    if (json_is_array(lst))
        return json_array_extend(lst, cur) >= 0;

    if (json_is_object(lst))
        return json_object_update(lst, cur) >= 0;

    return false;
}

static bool
cmd_delete(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const char *s = json_string_value(arg);

    if (json_is_array(cur)) {
        size_t indx;

        indx = convert_int(cur, s);
        if (indx == SIZE_MAX)
            return false;

        return json_array_remove(cur, indx) >= 0;
    }

    if (json_is_object(cur))
        return json_object_del(cur, s) >= 0;

    return false;
}

static bool
cmd_length(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    size_t count = 0;

    if (json_is_array(cur))
        count = json_array_size(cur);
    else if (json_is_object(cur))
        count = json_object_size(cur);
    else if (json_is_string(cur))
        count = json_string_length(cur);
    else
        return false;

    return json_array_insert_new(stk, 0, json_integer(count)) >= 0;
}

static bool
cmd_empty(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    if (json_is_array(cur))
        return json_array_clear(cur) >= 0;

    if (json_is_object(cur))
        return json_object_clear(cur) >= 0;

    return false;
}

static bool
cmd_get(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const char *s = json_string_value(arg);
    json_t *v = NULL;

    if (json_is_array(cur)) {
        size_t indx;

        indx = convert_int(cur, s);
        if (indx == SIZE_MAX)
            return false;

        v = json_array_get(cur, indx);
    } else if (json_is_object(cur)) {
        v = json_object_get(cur, s);
    } else {
        return false;
    }

    return json_array_insert(stk, 0, v) >= 0;
}

static bool
cmd_set(const json_t *arg, json_t *stk, json_t *cur, json_t *lst)
{
    const char *s = json_string_value(arg);

    if (json_is_array(lst)) {
        size_t indx;

        indx = convert_int(lst, s);
        if (indx == SIZE_MAX)
            return false;

        return json_array_set(lst, indx, cur) >= 0;
    }

    if (json_is_object(lst))
        return json_object_set(lst, s, cur) >= 0;

    return false;
}

static const jcmd_doc_t doc_not[] = {
    { .doc = "Invert the following assertion" },
    {}
};

static const jcmd_doc_t doc_object[] = {
    { .doc = "Assert TOP to be an object" },
    {}
};

static const jcmd_doc_t doc_array[] = {
    { .doc = "Assert TOP to be an array" },
    {}
};

static const jcmd_doc_t doc_string[] = {
    { .doc = "Assert TOP to be a string" },
    {}
};

static const jcmd_doc_t doc_int[] = {
    { .doc = "Assert TOP to be an integer" },
    {}
};

static const jcmd_doc_t doc_real[] = {
    { .doc = "Assert TOP to be a real" },
    {}
};

static const jcmd_doc_t doc_number[] = {
    { .doc = "Assert TOP to be a number" },
    {}
};

static const jcmd_doc_t doc_true[] = {
    { .doc = "Assert TOP to be true" },
    {}
};

static const jcmd_doc_t doc_false[] = {
    { .doc = "Assert TOP to be false" },
    {}
};

static const jcmd_doc_t doc_bool[] = {
    { .doc = "Assert TOP to be a boolean" },
    {}
};

static const jcmd_doc_t doc_null[] = {
    { .doc = "Assert TOP to be null" },
    {}
};

static const jcmd_doc_t doc_equal[] = {
    { .doc = "Assert TOP to be equal to PREV" },
    {}
};

static const jcmd_doc_t doc_json[] = {
    { .arg = "JSON", .doc = "Parse JSON constant, push onto TOP" },
    { .arg = "FILE", .doc = "Read from FILE, push onto TOP" },
    { .arg = "-",    .doc = "Read from STDIN, push onto TOP" },
    {}
};

static const jcmd_doc_t doc_quote[] = {
    { .arg = "STR",  .doc = "Convert STR to a string, push onto TOP" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc = "Write TOP to FILE" },
    { .arg = "-",    .doc = "Write TOP to STDOUT" },
    {}
};

static const jcmd_doc_t doc_foreach[] = {
    { .arg = "FILE", .doc = "Write TOP (obj./arr.) to FILE, one line/item" },
    { .arg = "-",    .doc = "Write TOP (obj./arr.) to STDOUT, one line/item" },
    {}
};

static const jcmd_doc_t doc_unquote[] = {
    { .arg = "FILE", .doc = "Write TOP (str.) to FILE without quotes" },
    { .arg = "-",    .doc = "Write TOP (str.) to STDOUT without quotes" },
    {}
};

static const jcmd_doc_t doc_copy[] = {
    { .doc = "Deep copy TOP, push onto TOP" },
    {}
};

static const jcmd_doc_t doc_query[] = {
    { .doc = "Query the stack by deep copying and pushing onto TOP" },
    {}
};

static const jcmd_doc_t doc_move[] = {
    { .arg = "#", .doc = "Move TOP back # places on the stack" },
    {}
};

static const jcmd_doc_t doc_unwind[] = {
    { .doc = "Discard TOP from the stack" },
    {}
};

static const jcmd_doc_t doc_trunc[] = {
    { .arg = "#",  .doc = "Shrink TOP (arr.) to length #" },
    { .arg = "-#", .doc = "Discard last # items from TOP (arr.)" },
    {}
};

static const jcmd_doc_t doc_insert[] = {
    { .arg = "#", .doc = "Insert TOP into PREV (arr.) at #" },
    {}
};

static const jcmd_doc_t doc_append[] = {
    { .doc = "Append TOP to the end of PREV (arr.)" },
    { .doc = "Set missing values from TOP (obj.) into PREV (obj.)" },
    {}
};

static const jcmd_doc_t doc_extend[] = {
    { .doc = "Append items from TOP to the end of PREV (arr.)" },
    { .doc = "Set all values from TOP (obj.) into PREV (obj.)" },
    {}
};

static const jcmd_doc_t doc_delete[] = {
    { .arg = "NAME", .doc = "Delete NAME from TOP (obj.)" },
    { .arg = "#",    .doc = "Delete # from TOP (arr.)" },
    { .arg = "-#",   .doc = "Delete # from the end of TOP (arr.)" },
    {}
};

static const jcmd_doc_t doc_length[] = {
    { .doc = "Push length of TOP (arr./str./obj.) to TOP" },
    {}
};

static const jcmd_doc_t doc_empty[] = {
    { .doc = "Erase all items from TOP (arr./obj.)" },
    {}
};

static const jcmd_doc_t doc_get[] = {
    { .arg = "NAME", .doc = "Get item with NAME from TOP (obj.), push to TOP" },
    { .arg = "#",    .doc = "Get # item from TOP (arr.), push to TOP" },
    { .arg = "-#",   .doc = "Get # item from the end of TOP (arr.), push to TOP" },
    {}
};

static const jcmd_doc_t doc_set[] = {
    { .arg = "NAME", .doc = "Sets TOP into PREV (obj.) with NAME" },
    { .arg = "#",    .doc = "Sets TOP into PREV (obj.) at #" },
    { .arg = "-#",   .doc = "Sets TOP into PREV (obj.) at # from the end" },
    {}
};

static const jcmd_doc_t doc_b64l[] = {
    { .doc = "URL-safe Base64 decode TOP (str.), push onto TOP" },
    {}
};

static const jcmd_doc_t doc_b64d[] = {
    { .doc = "URL-safe Base64 encode TOP, push onto TOP" },
    {}
};

static bool
opt_set_null(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **x = vopt;
    if (!*x) *x = json_array();
    return json_array_append_new(*x, json_pack("[i,n]", cfg->opt.val)) >= 0;
}


static bool
opt_set_str(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **x = vopt;
    if (!*x) *x = json_array();
    return json_array_append_new(*x, json_pack("[i,s]", cfg->opt.val, arg)) >= 0;
}

static bool
opt_set_int(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **x = vopt;
    json_int_t j = 0;
    int i = 0;

    if (sscanf(arg, "%d", &i) != 1)
        return false;

    j = i;
    if (!*x) *x = json_array();
    return json_array_append_new(*x, json_pack("[i,I]", cfg->opt.val, j)) >= 0;
}

static bool
opt_set_uint(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    unsigned int i = 0;
    json_t **x = vopt;
    json_int_t j = 0;

    if (sscanf(arg, "%u", &i) != 1)
        return false;

    j = i;
    if (!*x) *x = json_array();
    return json_array_append_new(*x, json_pack("[i,I]", cfg->opt.val, j)) >= 0;
}

static bool
opt_set_json(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_auto_t *j = NULL;
    json_t **x = vopt;

    if (!jcmd_opt_set_json(cfg, &j, arg))
        return false;

    if (!*x) *x = json_array();
    return json_array_append_new(*x, json_pack("[i,O]", cfg->opt.val, j)) >= 0;
}

static const jcmd_cfg_t cfgs[] = {
    { .opt = { "not",      no_argument,       .val = 'X' }, .doc = doc_not,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "object",   no_argument,       .val = 'O' }, .doc = doc_object,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "array",    no_argument,       .val = 'A' }, .doc = doc_array,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "string",   no_argument,       .val = 'S' }, .doc = doc_string,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "integer",  no_argument,       .val = 'I' }, .doc = doc_int,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "real",     no_argument,       .val = 'R' }, .doc = doc_real,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "number",   no_argument,       .val = 'N' }, .doc = doc_number,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "true",     no_argument,       .val = 'T' }, .doc = doc_true,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "false",    no_argument,       .val = 'F' }, .doc = doc_false,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "boolean",  no_argument,       .val = 'B' }, .doc = doc_bool,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "null",     no_argument,       .val = '0' }, .doc = doc_null,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "equal",    no_argument,       .val = 'E' }, .doc = doc_equal,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },

    { .opt = { "query",    no_argument,       .val = 'Q' }, .doc = doc_query,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "move",     required_argument, .val = 'M' }, .doc = doc_move,
      .set = opt_set_uint, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "unwind",   no_argument,       .val = 'U' }, .doc = doc_unwind,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },

    { .opt = { "json",     required_argument, .val = 'j' }, .doc = doc_json,
      .set = opt_set_json, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "copy",     no_argument,       .val = 'c' }, .doc = doc_copy,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "quote",    required_argument, .val = 'q' }, .doc = doc_quote,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "output",   required_argument, .val = 'o' }, .doc = doc_output,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "foreach",  required_argument, .val = 'f' }, .doc = doc_foreach,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "unquote",  required_argument, .val = 'u' }, .doc = doc_unquote,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },

    { .opt = { "truncate", required_argument, .val = 't' }, .doc = doc_trunc,
      .set = opt_set_int,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "insert",   required_argument, .val = 'i' }, .doc = doc_insert,
      .set = opt_set_uint, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "append",   no_argument,       .val = 'a' }, .doc = doc_append,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "extend",   no_argument,       .val = 'x' }, .doc = doc_extend,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },

    { .opt = { "delete",   required_argument, .val = 'd' }, .doc = doc_delete,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "length",   no_argument,       .val = 'l' }, .doc = doc_length,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "empty",    no_argument,       .val = 'e' }, .doc = doc_empty,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "get",      required_argument, .val = 'g' }, .doc = doc_get,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "set",      required_argument, .val = 's' }, .doc = doc_set,
      .set = opt_set_str,  .off = offsetof(jcmd_opt_t, args) },

    { .opt = { "b64load",  no_argument,       .val = 'y' }, .doc = doc_b64l,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },
    { .opt = { "b64dump",  no_argument,       .val = 'Y' }, .doc = doc_b64d,
      .set = opt_set_null, .off = offsetof(jcmd_opt_t, args) },

    {}
};

static int
jcmd_fmt(int argc, char *argv[])
{
    json_auto_t *stk = json_array();
    jcmd_opt_auto_t opt = {};
    unsigned char ret = 0;
    bool not = false;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return -1;

    for (size_t i = 0; i < json_array_size(opt.args); i++) {
        json_t *lst = NULL;
        json_t *cur = NULL;
        json_t *p = NULL;
        bool ok = false;
        int o = 0;

        if (json_unpack(json_array_get(opt.args, i), "[i,o!]", &o, &p) < 0)
            return ++ret;

        if (not && !strchr("OASIRNTFB0E", o))
            return ret;

        cur = json_array_get(stk, 0);
        lst = json_array_get(stk, 1);
        ret++;

        switch (o) {
        case 'X': ok = not = true;                                break;
        case 'O': ok = not ^ json_is_object(cur);  not = false;   break;
        case 'A': ok = not ^ json_is_array(cur);   not = false;   break;
        case 'S': ok = not ^ json_is_string(cur);  not = false;   break;
        case 'I': ok = not ^ json_is_integer(cur); not = false;   break;
        case 'R': ok = not ^ json_is_real(cur);    not = false;   break;
        case 'N': ok = not ^ json_is_number(cur);  not = false;   break;
        case 'T': ok = not ^ json_is_true(cur);    not = false;   break;
        case 'F': ok = not ^ json_is_false(cur);   not = false;   break;
        case 'B': ok = not ^ json_is_boolean(cur); not = false;   break;
        case '0': ok = not ^ json_is_null(cur);    not = false;   break;
        case 'E': ok = not ^ json_equal(cur, lst); not = false;   break;
        case 'Q': ok = JAIN(stk, 0, json_deep_copy(stk)) >= 0;    break;
        case 'M': ok = cmd_move(p, stk, cur, lst);                break;
        case 'U': ok = json_array_remove(stk, 0) >= 0;            break;
        case 'j': ok = json_array_insert(stk, 0, p) >= 0;         break;
        case 'c': ok = JAIN(stk, 0, json_deep_copy(cur)) >= 0;    break;
        case 'q': ok = json_array_insert(stk, 0, p) >= 0;         break;
        case 'o': ok = cmd_output(p, stk, cur, lst);              break;
        case 'f': ok = cmd_foreach(p, stk, cur, lst);             break;
        case 'u': ok = cmd_unquote(p, stk, cur, lst);             break;
        case 't': ok = cmd_trunc(p, stk, cur, lst);               break;
        case 'i': ok = cmd_insert(p, stk, cur, lst);              break;
        case 'a': ok = cmd_append(p, stk, cur, lst);              break;
        case 'x': ok = cmd_extend(p, stk, cur, lst);              break;
        case 'd': ok = cmd_delete(p, stk, cur, lst);              break;
        case 'l': ok = cmd_length(p, stk, cur, lst);              break;
        case 'e': ok = cmd_empty(p, stk, cur, lst);               break;
        case 'g': ok = cmd_get(p, stk, cur, lst);                 break;
        case 's': ok = cmd_set(p, stk, cur, lst);                 break;
        case 'Y': ok = JAIN(stk, 0, jose_b64_enc_dump(cur)) >= 0; break;
        case 'y': ok = JAIN(stk, 0, jose_b64_dec_load(cur)) >= 0; break;
        default:  ok = false;                                     break;
        }

        if (!ok)
            return ret;
    }

    if (not)
        return ret;

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_fmt, "fmt")
