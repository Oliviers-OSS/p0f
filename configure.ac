dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
AC_INIT(p0f, 3.09b,lcamtuf@coredump.cx)
AC_CONFIG_SRCDIR([p0f.c])
dnl AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM

dnl Initialize automake
dnl AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects]) 
dnl https://stackoverflow.com/questions/21609580/autotools-build-fails-due-to-subdir-objects-option-in-am-init-automake
AM_INIT_AUTOMAKE([dist-bzip2])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h locale.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 memmove memset setlocale socket strcasecmp strchr strncasecmp strstr tzset])

AC_CHECK_LIB(pcap, pcap_open_live)


# Checks for pkg config and needed parameters files
#PKG_CHECK_MODULES(LIBPCAP, [libpcap],,
#    AC_MSG_ERROR([You need the pcap library]
#    [])
#)

dnl parameters
AC_CONFIG_FILES(Makefile 	
	)
AC_OUTPUT

