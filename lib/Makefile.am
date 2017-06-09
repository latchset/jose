AM_CFLAGS = \
    @libcrypto_CFLAGS@ \
    @jansson_CFLAGS@ \
    @zlib_CFLAGS@ \
    @JOSE_CFLAGS@ \
    -I $(top_srcdir) \
    -pthread

lib_LTLIBRARIES = libjose.la

libjose_la_LDFLAGS = $(LDFLAGS)

libjose_la_LIBADD = \
    @libcrypto_LIBS@ \
    @jansson_LIBS@ \
    @zlib_LIBS@

libjose_la_SOURCES = \
    misc.c misc.h \
    cfg.c \
    io.c \
    b64.c \
    hsh.c hsh.h \
    hooks.c hooks.h \
    jwk.c \
    jws.c \
    jwe.c \
    zlib/deflate.c \
    openssl/aescbch.c \
    openssl/aesgcm.c \
    openssl/aesgcmkw.c \
    openssl/aeskw.c \
    openssl/compat.c openssl/compat.h \
    openssl/dir.c \
    openssl/ec.c \
    openssl/ecdh.c \
    openssl/ecdhes.c \
    openssl/ecmr.c \
    openssl/ecdsa.c \
    openssl/hash.c \
    openssl/hmac.c \
    openssl/jwk.c \
    openssl/lock.c \
    openssl/misc.c openssl/misc.h \
    openssl/oct.c \
    openssl/pbes2.c \
    openssl/rsa.c \
    openssl/rsaes.c \
    openssl/rsassa.c

EXTRA_DIST = libjose.map

if HAVE_LD_VERSION_SCRIPT
libjose_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libjose.map
else
libjose_la_LDFLAGS += -export-symbols-regex '^jose_.*' -version-info 1:0:0
endif
