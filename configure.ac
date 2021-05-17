#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(pcap2wav, 1.0, daveh@beachdognet.com)
AM_INIT_AUTOMAKE([subdir-objects -Wno-portability])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

# Checks for endianness
AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

case $host_os in
*darwin* | *rhapsody* | *macosx*)
     AM_CONDITIONAL(OSX, true)
     AM_CONDITIONAL(LINUX, false)
     ;;
*)
     AM_CONDITIONAL(LINUX, true)
     AM_CONDITIONAL(OSX, false)
     ;;
esac

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
