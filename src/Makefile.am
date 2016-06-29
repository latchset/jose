SUBDIRS = . tests jose

AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@ @zlib_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = conv.h hook.h
inc_HEADERS = b64.h jwk.h jwkset.h jws.h jwe.h
lib_LTLIBRARIES = libjose.la

libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@ @zlib_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'
libjose_la_SOURCES = \
    hook.c \
    conv.c \
    hooks/hmac.c \
    hooks/ecdsa.c \
    hooks/rsassa.c \
    hooks/aescbch.c \
    hooks/aesgcm.c \
    hooks/rsaes.c \
    hooks/aeskw.c \
    hooks/deflate.c \
    b64.c \
    jwk.c \
    jwkset.c \
    jws.c \
    jwe.c
