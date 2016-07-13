AM_CFLAGS = @JOSE_CFLAGS@ @jansson_CFLAGS@ @libcrypto_CFLAGS@ @zlib_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

inc_HEADERS = jose/b64.h jose/jwk.h jose/jws.h jose/jwe.h jose/openssl.h


lib_LTLIBRARIES = libjose.la
libjose_la_LIBADD = @jansson_LIBS@ @zlib_LIBS@ @libcrypto_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = \
    lib/misc.c lib/misc.h \
    lib/b64.c \
    lib/jwk.c \
    lib/jws.c \
    lib/jwe.c \
    lib/dir.c \
    lib/openssl/misc.c lib/openssl/misc.h \
    lib/openssl/jwk.c \
    lib/openssl/hmac.c \
    lib/openssl/ecdsa.c \
    lib/openssl/ecdhes.c \
    lib/openssl/rsassa.c \
    lib/openssl/aescbch.c \
    lib/openssl/aesgcm.c \
    lib/openssl/rsaes.c \
    lib/openssl/pbes2.c \
    lib/openssl/aeskw.c \
    lib/openssl/oct.c \
    lib/openssl/rsa.c \
    lib/openssl/ec.c \
    lib/zlib/deflate.c


bin_PROGRAMS = cmd/jose
cmd_jose_LDADD = libjose.la
cmd_jose_SOURCES = \
    cmd/gen.c \
    cmd/pub.c \
    cmd/sig.c \
    cmd/ver.c \
    cmd/enc.c \
    cmd/dec.c \
    cmd/jose.c \
    cmd/jose.h


EXTRA_DIST = tests/vectors
TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)
check_HEADERS = tests/vect.h tests/jtbl.h
dist_check_SCRIPTS = tests/rfc7515_A tests/rfc7520_4 tests/rfc7520_5 tests/jose
check_PROGRAMS = tests/b64 tests/jwk
check_LTLIBRARIES = tests/libtest.la
tests_libtest_la_SOURCES = tests/vect.c tests/jtbl.c
tests_b64_LDADD = libjose.la tests/libtest.la
tests_b64_SOURCES = tests/b64.c
tests_jwk_LDADD = libjose.la tests/libtest.la
tests_jwk_SOURCES = tests/jwk.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = jose.pc
