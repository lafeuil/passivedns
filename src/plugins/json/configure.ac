#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([json], [1.2.0])
AM_INIT_AUTOMAKE
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([json.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Enable debug output.
AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug], [Enable debug output]))

AS_IF([test "x$enable_debug" = "xyes"], [
    CPPFLAGS="${CPPFLAGS} -Wall -g -DDEBUG"
])

# Enable gcc profile info.
AC_ARG_ENABLE(gccprofile,
    AS_HELP_STRING([--enable-gccprofile], [Enable gcc profile info (set -pg flag)]))

AS_IF([test "x$enable_gccprofile" = "xyes"], [
    CPPFLAGS="${CPPFLAGS} -g -pg"
])

# Checks for ldns.
AC_ARG_WITH(ldns_includes,
    [  --with-ldns-includes=DIR      ldns include directory],
    [with_ldns_includes="$withval"],[with_ldns_includes="no"])

AC_ARG_WITH(ldns_libraries,
    [  --with-ldns-libraries=DIR     ldns library directory],
    [with_ldns_libraries="$withval"],[with_ldns_libraries="no"])

if test "$with_ldns_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_ldns_includes}"
fi

if test "$with_ldns_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_ldns_libraries}"
fi

LDFLAGS="${LDFLAGS} -lldns"

# Check or ldns headers
AC_CHECK_HEADER(ldns/ldns.h,,LIBLDNS_H="no")

if test "$LIBLDNS_H" = "no"; then
    echo -e "\n  ERROR! ldns headers not found\n"
    exit 1
fi

# Check for ldns library
AC_CHECK_LIB(ldns,ldns_pkt_get_rcode,,LIBLDNS_L="no")

if test "$LIBLDNS_L" = "no"; then
    echo -e "\n  ERROR! ldns library not found\n"
    exit 1
fi

# Checks for libjansson.
AC_ARG_WITH(jansson_includes,
    [  --with-jansson-includes=DIR   libjansson include directory],
    [with_jansson_includes="$withval"],[with_jansson_includes="no"])

AC_ARG_WITH(jansson_libraries,
    [  --with-jansson-libraries=DIR  libjansson library directory],
    [with_jansson_libraries="$withval"],[with_jansson_libraries="no"])

if test "$with_jansson_includes" != "no"; then
  CPPFLAGS="${CPPFLAGS} -I${with_jansson_includes}"
fi

if test "$with_jansson_libraries" != "no"; then
  LDFLAGS="${LDFLAGS} -L${with_jansson_libraries}"
fi

LDFLAGS="${LDFLAGS} -ljansson"

# Check for jansson headers
AC_CHECK_HEADER(jansson.h,,LIBJANSSON_H="no")

if test "$LIBJANSSON_H" = "no"; then
  echo -e "\n  ERROR! Jansson headers not found\n"
  exit 1
fi

# Check for jansson library
AC_CHECK_LIB(jansson,json_delete,,LIBJANSSON_L="no")

if test "$LIBJANSSON_L" = "no"; then
  echo -e "\n  ERROR! Jansson library not found\n"
  exit 1
fi

CPPFLAGS="${CPPFLAGS} -I../.."
LDFLAGS="${LDFLAGS} -L../.."

LT_INIT

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([alarm dup2 endgrent endpwent ftruncate getcwd memset strdup strerror strtol strtoul])

AC_OUTPUT(Makefile)

