# Netify Agent
# GNU Autoconf configuration

AC_PREREQ([2.63])
AC_INIT([Netify Agent], [2.6],
    [https://github.com/eglooca/netify-daemon/issues],
    [netifyd], [http://www.egloo.ca/])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/netifyd.cpp])
AC_CONFIG_SUBDIRS([inih ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([_ND_CANONICAL_HOST], ["${host_os}"], [Defines the canonical host.])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG([0.23])
AC_PATH_PROG([bash], [bash], [false])

AS_IF([test "x$ac_cv_path_bash" != "xfalse"], [
    AC_SUBST([ND_PATH_BASH], [$ac_cv_path_bash])
], [
    AC_MSG_ERROR([bash not found.])
])

# Checks for libraries.
AC_CHECK_LIB([pcap],
    [pcap_open_live], [], [AC_MSG_ERROR([libpcap/pcap_open_live() not found.])])
AC_CHECK_LIB([pthread],
    [pthread_create], [], [AC_MSG_ERROR([libpthread/pthread_create() not found.])])
AC_CHECK_LIB([rt],
    [timer_create], [], [AC_MSG_ERROR([librt/timer_create() not found.])])
case "${host_os}" in
    linux*)
        AC_CHECK_LIB([resolv],
            [ns_initparse], [], [AC_MSG_ERROR([libresolv/ns_initparse() not found.])])
        ;;
esac

#AC_CHECK_LIB([libmbedtls.so.9], [ssl_init])

PKG_CHECK_MODULES([JSONC], [json-c])
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([ZLIB], [zlib])

# Parameters: --with/without
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

# Parameters: --enable/disable
AC_ARG_ENABLE([conntrack],
    [AS_HELP_STRING([--enable-conntrack], [Enable connection tracking support [default=yes]])],
    [],
    [enable_conntrack=yes])

AS_IF([test "x$enable_conntrack" = "xyes"], [
    AC_DEFINE([_ND_USE_CONNTRACK], [1],
        [Define to enable connection tracking support.])
    AM_CONDITIONAL(USE_CONNTRACK, true)
    PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
    PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.4])
], [
    AM_CONDITIONAL(USE_CONNTRACK, false)
])

AC_ARG_ENABLE([inotify],
    [AS_HELP_STRING([--enable-inotify], [Enable inotify file watch support [default=yes]])],
    [],
    [enable_inotify=yes])

AS_IF([test "x$enable_inotify" = "xyes"], [
    AC_DEFINE([_ND_USE_INOTIFY], [1],
        [Define to enable inotify file watch support.])
    AM_CONDITIONAL(USE_INOTIFY, true)
    AC_CHECK_HEADERS([sys/inotify.h], [], AC_MSG_ERROR([inotify header(s) not found.]))
], [
    AM_CONDITIONAL(USE_INOTIFY, false)
])

AC_ARG_ENABLE([ncurses],
    [AS_HELP_STRING([--enable-ncurses], [Enable ncurses debug screen [default=yes]])],
    [],
    [enable_ncurses=yes])

AS_IF([test "x$enable_ncurses" = "xyes"], [
    AC_DEFINE([_ND_USE_NCURSES], [1],
        [Define to enable ncurses debug screen.])
    AM_CONDITIONAL(USE_NCURSES, true)
    PKG_CHECK_MODULES([LIBNCURSES], [ncurses])
], [
    AM_CONDITIONAL(USE_NCURSES, false)
])

AC_ARG_ENABLE([netlink],
    [AS_HELP_STRING([--enable-netlink], [Enable Netlink socket support [default=yes]])],
    [],
    [enable_netlink=yes])

AS_IF([test "x$enable_netlink" = "xyes"], [
    AC_DEFINE([_ND_USE_NETLINK], [1],
        [Define to enable Netlink socket support.])
    AM_CONDITIONAL(USE_NETLINK, true)
    AC_CHECK_HEADERS([linux/netlink.h], [], AC_MSG_ERROR([netlink header(s) not found.]))
], [
    AM_CONDITIONAL(USE_NETLINK, false)
])

# Checks for required header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h net/ethernet.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/types.h sys/time.h sys/un.h syslog.h unistd.h], [], AC_MSG_ERROR([required header(s) not found.]))
AC_CHECK_HEADERS([netinet/in.h netinet/ip.h netinet/tcp.h netinet/udp.h], [], AC_MSG_ERROR([required netinet header(s) not found.]),
[[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])

# Check for optional header files.
AC_CHECK_HEADERS([endian.h net/ppp_defs.h linux/ppp_defs.h])

# Check compiler flags (gnu++11)
m4_include([m4/ax_cxx_compile_stdcxx_0x.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

# Check for optional parameters

# Checks for typedefs, structures, sizes, and compiler characteristics.
#AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_SIZEOF([long])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN

AC_CHECK_FUNCS([ftruncate memchr memset pathconf select socket strcasecmp strdup strerror])

AC_CHECK_FUNC([pthread_setname_np], [
    AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if pthread_setname_np is available.])
])
AC_CHECK_FUNC([pthread_attr_setaffinity_np], [
    AC_DEFINE([HAVE_PTHREAD_ATTR_SETAFFINITY_NP], [1], [Define if pthread_attr_setaffinity_np is available.])
])

# Compiler optimizations
#CFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"
#CXXFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"

# Get git revision
if test -d ".git"; then :
    GIT_TAG=`git log -1 --format=%h`
    GIT_DATE=`git log -1 --format=%cd`

    # On CentOS 6 `git rev-list HEAD --count` does not work
    GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
    GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
else
    GIT_RELEASE="${PACKAGE_VERSION}"
    GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])

# Output files
AC_CONFIG_FILES([Makefile deploy/Makefile doc/Makefile src/Makefile util/Makefile netifyd.spec])
AC_CONFIG_FILES([debian/debian.changelog debian/debian.control debian/debian.rules debian/netifyd.dsc])
AC_CONFIG_FILES([openwrt/net/netifyd/Makefile])
AC_CONFIG_FILES([util/generate-json-include.sh], [chmod +x util/generate-json-include.sh])
AC_CONFIG_FILES([util/generate-protocol-csv.sh], [chmod +x util/generate-protocol-csv.sh])
AC_OUTPUT
