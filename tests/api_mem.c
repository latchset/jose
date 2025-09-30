/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2025 Red Hat, Inc.
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

#include <jose/jose.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static struct {
    size_t malloc_calls;
    size_t realloc_calls;
    size_t free_calls;
    size_t total_allocated;
    size_t total_freed;
    int fail_malloc;
    int fail_realloc;
} alloc_stats = {0};

static void*
test_malloc(size_t size)
{
    alloc_stats.malloc_calls++;
    
    if (alloc_stats.fail_malloc)
        return NULL;
    
    void *ptr = malloc(size);
    if (ptr) {
        alloc_stats.total_allocated += size;
    }
    return ptr;
}

static void*
test_realloc(void *ptr, size_t size)
{
    alloc_stats.realloc_calls++;
    
    if (alloc_stats.fail_realloc)
        return NULL;
    
    return realloc(ptr, size);
}

static void
test_free(void *ptr)
{
    alloc_stats.free_calls++;
    
    if (ptr) {
        free(ptr);
    }
}

static void*
test_calloc(size_t nmemb, size_t size)
{
    alloc_stats.malloc_calls++; // calloc is effectively malloc + zero
    
    if (alloc_stats.fail_malloc)
        return NULL;
    
    void *ptr = calloc(nmemb, size);
    if (ptr) {
        alloc_stats.total_allocated += nmemb * size;
    }
    return ptr;
}

static void
reset_alloc_stats(void)
{
    memset(&alloc_stats, 0, sizeof(alloc_stats));
}

static void
test_allocator_set_get(void)
{
    // Store original allocators
    jose_malloc_t orig_malloc;
    jose_realloc_t orig_realloc;
    jose_free_t orig_free;
    jose_calloc_t orig_calloc;
    jose_get_alloc(&orig_malloc, &orig_realloc, &orig_free, &orig_calloc);
    
    // Set our test allocators
    int ret = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret == 0);
    
    // Verify they were set correctly
    jose_malloc_t curr_malloc;
    jose_realloc_t curr_realloc;
    jose_free_t curr_free;
    jose_calloc_t curr_calloc;
    jose_get_alloc(&curr_malloc, &curr_realloc, &curr_free, &curr_calloc);
    assert(curr_malloc == test_malloc);
    assert(curr_realloc == test_realloc);
    assert(curr_free == test_free);
    assert(curr_calloc == test_calloc);
    
    // Reset to originals
    ret = jose_set_alloc(orig_malloc, orig_realloc, orig_free, orig_calloc);
    assert(ret == 0);
    
    // Verify reset worked
    jose_get_alloc(&curr_malloc, &curr_realloc, &curr_free, &curr_calloc);
    assert(curr_malloc == orig_malloc);
    assert(curr_realloc == orig_realloc);
    assert(curr_free == orig_free);
    assert(curr_calloc == orig_calloc);
}

static void
test_allocator_io_operations(void)
{
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    int ret = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    void *buf = NULL;
    size_t len = 0;
    
    jose_io_t *io = jose_io_malloc(cfg, &buf, &len);
    assert(io != NULL);
    assert(alloc_stats.malloc_calls > 0);
    
    const char *test_data = "Hello, world! This is test data for the custom allocator.";
    size_t data_len = strlen(test_data);
    
    assert(io->feed(io, test_data, data_len));
    assert(alloc_stats.realloc_calls > 0);
    
    assert(io->done(io));
    
    assert(buf != NULL);
    assert(len == data_len);
    assert(memcmp(buf, test_data, data_len) == 0);
    
    size_t initial_free_calls = alloc_stats.free_calls;
    jose_io_decref(io);
    assert(alloc_stats.free_calls > initial_free_calls);
                
    printf("Allocator IO operations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
}

static void
test_allocator_failures(void)
{
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    int ret = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    alloc_stats.fail_malloc = 1;
    
    void *buf = NULL;
    size_t len = 0;
    
    jose_io_t *io = jose_io_malloc(cfg, &buf, &len);
    assert(io == NULL);
    assert(alloc_stats.malloc_calls > 0);
    
    alloc_stats.fail_malloc = 0;
    
    reset_alloc_stats();
    
    printf("Allocator failure tests - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
}

static void
test_multiple_configs(void)
{
    jose_cfg_auto_t *cfg1 = jose_cfg();
    jose_cfg_auto_t *cfg2 = jose_cfg();
    assert(cfg1 != NULL);
    assert(cfg2 != NULL);
    
    int ret1 = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret1 == 0);
    
    reset_alloc_stats();
    
    jose_malloc_t malloc_func1 = NULL, malloc_func2 = NULL;
    jose_get_alloc(&malloc_func1, NULL, NULL, NULL);
    jose_get_alloc(&malloc_func2, NULL, NULL, NULL);
    
    assert(malloc_func1 == test_malloc);
    assert(malloc_func2 == test_malloc);
    
    reset_alloc_stats();
    
    void *buf1 = NULL;
    size_t len1 = 0;
    jose_io_t *io1 = jose_io_malloc(cfg1, &buf1, &len1);
    assert(io1 != NULL);
    
    size_t custom_malloc_calls = alloc_stats.malloc_calls;
    assert(custom_malloc_calls > 0);
    
    void *buf2 = NULL;
    size_t len2 = 0;
    jose_io_t *io2 = jose_io_malloc(cfg2, &buf2, &len2);
    assert(io2 != NULL);
    
    assert(alloc_stats.malloc_calls > custom_malloc_calls);
    
    jose_io_decref(io1);
    jose_io_decref(io2);
    
    printf("Multiple configurations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
}

static void
test_null_config(void)
{
    jose_reset_alloc();
    
    void *buf = NULL;
    size_t len = 0;
    
    reset_alloc_stats();
    
    jose_io_t *io = jose_io_malloc(NULL, &buf, &len);
    assert(io != NULL);
    
    assert(alloc_stats.malloc_calls == 0);
    assert(alloc_stats.realloc_calls == 0);
    assert(alloc_stats.free_calls == 0);
    
    const char *test_data = "Test data";
    assert(io->feed(io, test_data, strlen(test_data)));
    assert(io->done(io));
    
    assert(alloc_stats.malloc_calls == 0);
    assert(alloc_stats.realloc_calls == 0);
    assert(alloc_stats.free_calls == 0);
    
    assert(buf != NULL);
    assert(len == strlen(test_data));
    assert(memcmp(buf, test_data, len) == 0);
    
    jose_io_decref(io);
    
    printf("NULL config - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
}

static void
test_allocator_with_jws(void)
{
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    int ret = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    json_auto_t *jwk = json_pack("{s:s}", "alg", "HS256");
    assert(jwk != NULL);
    assert(jose_jwk_gen(cfg, jwk));
    
    json_auto_t *jws = json_pack("{s:s}", "payload", "test payload");
    assert(jws != NULL);
    assert(jose_jws_sig(cfg, jws, NULL, jwk));
    
    assert(jose_jws_ver(cfg, jws, NULL, jwk, false));
    
    printf("  JWS operations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
    
    printf("JWS operations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
}

static void
test_global_allocators_with_b64(void)
{
    jose_cfg_auto_t *cfg = jose_cfg();
    assert(cfg != NULL);
    
    int ret = jose_set_alloc(test_malloc, test_realloc, test_free, test_calloc);
    assert(ret == 0);
    
    reset_alloc_stats();
    
    json_auto_t *test_json = json_pack("{s:s,s:i}", "message", "Hello, World!", "value", 42);
    assert(test_json != NULL);
    
    json_auto_t *encoded = jose_b64_enc_dump(test_json);
    assert(encoded != NULL);
    
    json_auto_t *decoded = jose_b64_dec_load(encoded);
    assert(decoded != NULL);
    
    const char *message = NULL;
    int value = 0;
    assert(json_unpack(decoded, "{s:s,s:i}", "message", &message, "value", &value) == 0);
    assert(strcmp(message, "Hello, World!") == 0);
    assert(value == 42);
    
    assert(alloc_stats.malloc_calls > 0);
    assert(alloc_stats.free_calls > 0);
    
    printf("  B64 operations - malloc calls: %zu, realloc calls: %zu, free calls: %zu\n",
           alloc_stats.malloc_calls, alloc_stats.realloc_calls, alloc_stats.free_calls);
    
}

int
main(int argc, char *argv[])
{
    
    test_allocator_set_get();
    test_allocator_io_operations();
    test_allocator_failures();
    test_multiple_configs();
    test_null_config();
    test_allocator_with_jws();
    test_global_allocators_with_b64();
    
    
    return EXIT_SUCCESS;
}
