#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([iosocks], [1.2.0], [i@xiaoxiao.im], [iosocks], [https://github.com/XiaoxiaoPu/iosocks])
AC_CONFIG_SRCDIR([iosocks])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR(auto)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_INSTALL

AC_ARG_ENABLE(
    [assembly],
    [AS_HELP_STRING([--disable-assembly], [disable inline assembly])],
    [
        case "${enableval}" in
            yes) assembly=true ;;
            no)  assembly=false ;;
            *)   AC_MSG_ERROR(bad value ${enableval} for --disable-assembly) ;;
        esac
    ],
    [assembly=true]
)
if test "${assembly}" = "true" ; then
    AC_DEFINE([USE_ASSEMBLY], [1], [Use assembly to boost RC4])
fi

AC_ARG_ENABLE(
    [debug],
    [AS_HELP_STRING([--enable-debug], [build with additional debugging code])],
    [
        CFLAGS='-g -DDEBUG -fprofile-arcs -ftest-coverage -O0'
    ]
)
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

# Checks for libraries.
ANL_LIBS="-lanl"
EV_LIBS="-lev"
AC_CHECK_LIB([anl], [getaddrinfo_a], [AC_SUBST(ANL_LIBS)])
AC_CHECK_LIB([ev], [ev_default_loop], [AC_SUBST(EV_LIBS)])

# Checks for header files.
AC_HEADER_ASSERT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h grp.h netdb.h netinet/in.h pwd.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([linux/if.h linux/netfilter_ipv4.h linux/netfilter_ipv6/ip6_tables.h],
    [], [AC_MSG_ERROR([Missing netfilter headers])],
    [[
    #if HAVE_LIMITS_H
    #include <limits.h>
    #endif
    /* Netfilter ip(6)tables v1.4.0 has broken headers */
    #if HAVE_NETINET_IN_H
    #include <netinet/in.h>
    #endif
    #if HAVE_LINUX_IF_H
    #include <net/if.h>
    #endif
    #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
    #endif
    ]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero popen pclose setresuid setreuid socket strchr strdup strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
