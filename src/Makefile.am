SUBDIRS = . tests jose

AM_CFLAGS = @JOSE_CFLAGS@ @jansson_CFLAGS@ @libcrypto_CFLAGS@ @zlib_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = core.h misc.h
inc_HEADERS = b64.h jwk.h jws.h jwe.h openssl.h

noinst_LTLIBRARIES = libcore.la
libcore_la_SOURCES = core.c

lib_LTLIBRARIES = libjose.la libjose-openssl.la libjose-zlib.la

libjose_la_LIBADD = libcore.la @jansson_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = misc.c b64.c jwk.c jws.c jwe.c

libjose_openssl_la_LIBADD = libjose.la @libcrypto_LIBS@
libjose_openssl_la_LDFLAGS = -export-symbols-regex '^jose_openssl_'
libjose_openssl_la_SOURCES = \
    openssl/misc.c \
    openssl/jwk.c \
    openssl/hmac.c \
    openssl/ecdsa.c \
    openssl/rsassa.c \
    openssl/aescbch.c \
    openssl/aesgcm.c \
    openssl/rsaes.c \
    openssl/aeskw.c \
    openssl/oct.c \
    openssl/rsa.c \
    openssl/ec.c

libjose_zlib_la_LIBADD = libjose.la @zlib_LIBS@
libjose_zlib_la_SOURCES = zlib/deflate.c
