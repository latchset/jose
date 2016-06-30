AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@ @zlib_CFLAGS@

bin_PROGRAMS = jose
jose_LDADD = ../libcore.la ../libjose-openssl.la ../libjose-zlib.la
jose_SOURCES = gen.c pub.c sig.c ver.c enc.c dec.c jose.c jose.h
