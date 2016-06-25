AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

bin_PROGRAMS = jose
jose_LDADD = libjose.la

noinst_HEADERS = conv.h hmac.h ecdsa.h rsassa.h aescbch.h aesgcm.h rsaes.h aeskw.h
inc_HEADERS = b64.h jwk.h jwkset.h jws.h jwe.h
lib_LTLIBRARIES = libint.la libjose.la

libint_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@
libint_la_SOURCES = \
    conv.c \
    hmac.c \
    ecdsa.c \
    rsassa.c \
    aescbch.c \
    aesgcm.c \
    rsaes.c \
    aeskw.c

libjose_la_LIBADD = libint.la
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = \
    b64.c \
    jwk.c \
    jwkset.c \
    jws.c \
    jwe.c

check_HEADERS = vect.h jtbl.h
check_PROGRAMS = hmac_t b64_t jwk_t jwkset_t jws_t jwe_t
check_LTLIBRARIES = libtest.la

libtest_la_SOURCES = vect.c jtbl.c

hmac_t_LDADD = libint.la libjose.la libtest.la

b64_t_LDADD = libint.la libjose.la libtest.la
jwk_t_LDADD = libint.la libjose.la libtest.la
jwkset_t_LDADD = libint.la libjose.la libtest.la
jws_t_LDADD = libint.la libjose.la libtest.la
jwe_t_LDADD = libint.la libjose.la libtest.la

TESTS = $(check_PROGRAMS)
