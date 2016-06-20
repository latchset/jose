AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = conv.h
inc_HEADERS = buf.h b64.h jwk.h jwkset.h jws.h
lib_LTLIBRARIES = libjose.la
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = \
    buf.c \
    b64.c \
    conv.c \
    jwk.c \
    jwkset.c \
    jws.c \
    jws_sig.c \
    jws_ver.c \
    jwe.c \
    jwe_encrypt.c \
    jwe_seal.c \
    jwe_unseal.c \
    jwe_decrypt.c

check_HEADERS = vect.h jtbl.h
check_PROGRAMS = b64_t jwk_t jwkset_t jws_t jwe_t
check_LTLIBRARIES = libtest.la
libtest_la_SOURCES = vect.c jtbl.c
b64_t_LDADD = libjose.la libtest.la
jwk_t_LDADD = libjose.la libtest.la
jwkset_t_LDADD = libjose.la libtest.la
jws_t_LDADD = libjose.la libtest.la
jwe_t_LDADD = libjose.la libtest.la

TESTS = $(check_PROGRAMS)

