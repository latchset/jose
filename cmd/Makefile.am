AM_CFLAGS = @JOSE_CFLAGS@ @jansson_CFLAGS@ -I$(top_srcdir) -I$(top_builddir)
LDFLAGS += ../lib/libjose.la @jansson_LIBS@

bin_PROGRAMS = jose
jose_SOURCES = \
    jose.c jose.h \
    b64/b64.h \
    b64/dec.c \
    b64/enc.c \
    jwk/jwk.h \
    jwk/eql.c \
    jwk/exc.c \
    jwk/gen.c \
    jwk/pub.c \
    jwk/thp.c \
    jwk/use.c \
    jws/jws.h \
    jws/fmt.c \
    jws/sig.c \
    jws/ver.c \
    jwe/jwe.h \
    jwe/fmt.c \
    jwe/dec.c \
    jwe/enc.c \
    alg.c \
    fmt.c
