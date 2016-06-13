AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = bn.h
inc_HEADERS = key.h b64.h jwk.h jwkset.h jws.h jose.h
lib_LTLIBRARIES = libjose.la
libjose_la_SOURCES = key.c b64.c bn.c jwk.c jwkset.c jws.c
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@

check_PROGRAMS = b64_t jwk_t jwkset_t jws_t
b64_t_LDADD = libjose.la
jwk_t_LDADD = libjose.la
jwkset_t_LDADD = libjose.la
jws_t_LDADD = libjose.la

TESTS = $(check_PROGRAMS)

