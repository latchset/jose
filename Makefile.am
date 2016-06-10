AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

pkgconfigdir = $(libdir)/pkgconfig

lib_LTLIBRARIES = libjose.la
include_HEADERS = jose.h
pkgconfig_DATA = jose.pc
noinst_HEADERS = json.h

libjose_la_SOURCES = key.c json.c jwk_ec.c jwk_oct.c jwk_rsa.c jws.c
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@

check_PROGRAMS = key_t
key_t_LDADD = libjose.la

TESTS = $(check_PROGRAMS)

