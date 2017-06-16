AC_PREREQ(2.62)
AC_INIT(jose, 9)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([zlib], [zlib])
PKG_CHECK_MODULES([jansson], [jansson >= 2.10])
PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.2])

AC_OPENMP
AC_SUBST([OPENMP_CFLAGS])

JOSE_CFLAGS="\
-Wall \
-Wextra \
-Werror \
-Wstrict-aliasing \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
-Wunused-function \
-Wno-missing-field-initializers \
-Wno-unused-command-line-argument \
-Wno-unused-parameter \
-Wno-unknown-pragmas \
"
AC_SUBST([JOSE_CFLAGS])

AC_MSG_CHECKING([for linker script support])
LDVS=`$LD --help < /dev/null 2>/dev/null | grep version-script`
if test "$LDVS"; then
    have_ld_version_script=yes
    AC_MSG_RESULT(yes)
else
    have_ld_version_script=no
    AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

AC_CONFIG_FILES([
    jose/Makefile
    lib/Makefile
    cmd/Makefile
    tests/Makefile
    doc/Makefile
    Makefile
    jose/jose.h
    jose.pc
])
AC_OUTPUT
