AC_INIT([zx2c4-pass], [0.1], [https://github.com/denimor/pidgin-zx2c4-pass/issues], [pidgin-zx2c4-pass], [https://github.com/denimor/pidgin-zx2c4-pass])

AC_CONFIG_SRCDIR([src/zx2c4-pass.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([dist-xz no-dist-gzip])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_PATH_PROG([PASS], [pass])
AC_DEFINE_UNQUOTED(PASS_SCRIPT, "$PASS", [Full path to pass script])

PKG_CHECK_MODULES([GLIB], [glib-2.0])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])

PKG_CHECK_MODULES([LIBPURPLE], [purple >= 2.0.0])
AC_SUBST([LIBPURPLE_CFLAGS])
AC_SUBST([LIBPURPLE_LIBS])

PKG_CHECK_MODULES([PIDGIN], [pidgin >= 2.0.0])
AC_SUBST([PIDGIN_CFLAGS])
AC_SUBST([PIDGIN_LIBS])

#~ AM_CONDITIONAL([INSTALL_TO_HOME], [test "x${prefix}" = "x${HOME}"])
#~ AM_COND_IF([INSTALL_TO_HOME], [DSTDIR=${prefix}/.purple/plugins], [DSTDIR=${libdir}/pidgin])

if test "x${prefix}" = "x${HOME}" ; then
	DSTDIR=${prefix}/.purple/plugins
else
	DSTDIR=${libdir}/pidgin
fi
AC_SUBST([DSTDIR])

AC_OUTPUT([Makefile src/Makefile])
