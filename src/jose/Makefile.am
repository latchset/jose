AM_CFLAGS = @JOSE_CFLAGS@ @libcrypto_CFLAGS@ @jansson_CFLAGS@ @zlib_CFLAGS@

bin_PROGRAMS = jose
jose_LDADD = ../libjose.la
jose_SOURCES = \
    generate.c \
    publicize.c \
    sign.c \
    verify.c \
    encrypt.c \
    decrypt.c \
    jose.c \
    jose.h
