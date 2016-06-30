AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@ @zlib_CFLAGS@
LIBS = ../libjose.la libtest.a

check_HEADERS = vect.h jtbl.h
check_PROGRAMS = b64 jwk jws jwe
check_LIBRARIES = libtest.a

libtest_a_SOURCES = vect.c jtbl.c

TESTS = $(check_PROGRAMS)
