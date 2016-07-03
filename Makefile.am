AM_CFLAGS = @JOSE_CFLAGS@ @jansson_CFLAGS@ @libcrypto_CFLAGS@ @zlib_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

inc_HEADERS = jose/b64.h jose/jwk.h jose/jws.h jose/jwe.h jose/openssl.h

noinst_LTLIBRARIES = core/libcore.la
core_libcore_la_SOURCES = core/core.c core/core.h

lib_LTLIBRARIES = lib/libjose.la lib/zlib/libjose-zlib.la lib/openssl/libjose-openssl.la
lib_libjose_la_LIBADD = core/libcore.la @jansson_LIBS@
lib_libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
lib_libjose_la_SOURCES = lib/misc.c lib/misc.h lib/b64.c lib/jwk.c lib/jws.c lib/jwe.c
lib_zlib_libjose_zlib_la_LIBADD = lib/libjose.la @zlib_LIBS@
lib_zlib_libjose_zlib_la_SOURCES = lib/zlib/deflate.c
lib_openssl_libjose_openssl_la_LIBADD = lib/libjose.la @libcrypto_LIBS@
lib_openssl_libjose_openssl_la_LDFLAGS = -export-symbols-regex '^jose_openssl_'
lib_openssl_libjose_openssl_la_SOURCES = \
    lib/openssl/misc.c \
    lib/openssl/jwk.c \
    lib/openssl/hmac.c \
    lib/openssl/ecdsa.c \
    lib/openssl/rsassa.c \
    lib/openssl/aescbch.c \
    lib/openssl/aesgcm.c \
    lib/openssl/rsaes.c \
    lib/openssl/aeskw.c \
    lib/openssl/oct.c \
    lib/openssl/rsa.c \
    lib/openssl/ec.c


bin_PROGRAMS = cmd/jose
cmd_jose_LDADD = core/libcore.la lib/zlib/libjose-zlib.la lib/openssl/libjose-openssl.la
cmd_jose_SOURCES = \
    cmd/gen.c \
    cmd/pub.c \
    cmd/sig.c \
    cmd/ver.c \
    cmd/enc.c \
    cmd/dec.c \
    cmd/jose.c \
    cmd/jose.h


TESTS = $(check_PROGRAMS) tests/jose
check_HEADERS = tests/vect.h tests/jtbl.h
check_PROGRAMS = tests/b64 tests/jwk tests/jws tests/jwe
check_LTLIBRARIES = tests/libtest.la
tests_libtest_la_SOURCES = tests/vect.c tests/jtbl.c
tests_b64_LDADD = lib/openssl/libjose-openssl.la lib/zlib/libjose-zlib.la core/libcore.la tests/libtest.la
tests_b64_SOURCES = tests/b64.c
tests_jwk_LDADD = lib/openssl/libjose-openssl.la lib/zlib/libjose-zlib.la core/libcore.la tests/libtest.la
tests_jwk_SOURCES = tests/jwk.c
tests_jws_LDADD = lib/openssl/libjose-openssl.la lib/zlib/libjose-zlib.la core/libcore.la tests/libtest.la
tests_jws_SOURCES = tests/jws.c
tests_jwe_LDADD = lib/openssl/libjose-openssl.la lib/zlib/libjose-zlib.la core/libcore.la tests/libtest.la
tests_jwe_SOURCES = tests/jwe.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = jose.pc
