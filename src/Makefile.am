AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@

incdir = $(includedir)/$(PACKAGE_NAME)

noinst_HEADERS = conv.h
inc_HEADERS = buf.h b64.h jwk.h jwkset.h jws.h
lib_LTLIBRARIES = libjose.la
libjose_la_SOURCES = buf.c b64.c conv.c jwk.c jwkset.c jws.c jws_sig.c jws_ver.c jwe.c jwe_enc.c jwe_dec.c
libjose_la_LIBADD = @libcrypto_LIBS@ @jansson_LIBS@
libjose_la_LDFLAGS = -export-symbols-regex '^jose_'

check_PROGRAMS = b64_t jwk_t jwkset_t jws_t jwe_t
b64_t_LDADD = libjose.la
jwk_t_LDADD = libjose.la
jwkset_t_LDADD = libjose.la
jws_t_LDADD = libjose.la
jwe_t_LDADD = libjose.la

TESTS = $(check_PROGRAMS)

