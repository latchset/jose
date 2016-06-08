AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

pkgconfigdir = $(libdir)/pkgconfig

lib_LTLIBRARIES = libjose.la
include_HEADERS = jose.h
pkgconfig_DATA = jose.pc
noinst_HEADERS = bin.h

libjose_la_SOURCES = bin.c jwk.c jws.c
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@

check_PROGRAMS = bin_t
bin_t_LDADD = libjose.la

TESTS = $(check_PROGRAMS)

