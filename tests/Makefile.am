AM_CFLAGS = @JOSE_CFLAGS@ @OPENMP_CFLAGS@ @jansson_CFLAGS@ -I$(top_srcdir) -I$(top_builddir)
LDFLAGS += $(top_builddir)/lib/libjose.la @jansson_LIBS@
EXTRA_DIST = vectors

AM_TESTS_ENVIRONMENT=PATH=$(top_builddir)/cmd:$(PATH) VECTORS=$(top_srcdir)/tests/vectors
TESTS = $(dist_check_SCRIPTS) $(check_PROGRAMS)

check_PROGRAMS = \
    alg_hash \
    alg_sign \
    alg_encr \
    alg_wrap \
    alg_comp \
    api_b64 \
    api_jws \
    api_jwe

dist_check_SCRIPTS = \
    jose-alg \
    jose-fmt \
    jose-b64-enc \
    jose-b64-dec \
    jose-jwk-eql \
    jose-jwk-exc \
    jose-jwk-gen \
    jose-jwk-pub \
    jose-jwk-use \
    jose-jwk-thp \
    jose-jws-fmt \
    jose-jws-ver \
    jose-jws-sig \
    jose-jwe-fmt \
    jose-jwe-dec \
    jose-jwe-enc
