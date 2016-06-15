AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = conv.h
inc_HEADERS = buf.h b64.h jwk.h jwkset.h jws.h
lib_LTLIBRARIES = libjose.la
libjose_la_SOURCES = buf.c b64.c conv.c jwk.c jwkset.c jws.c ecdsa.c rsassa.c hmac.c
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@

check_PROGRAMS = b64_t jwk_t jwkset_t jws_t
b64_t_LDADD = libjose.la
jwk_t_LDADD = libjose.la
jwkset_t_LDADD = libjose.la
jws_t_LDADD = libjose.la

TESTS = $(check_PROGRAMS)

