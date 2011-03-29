#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([mod_vhost_ldap_n],[1.1.x])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([mod_vhost_ldap_ng.c])
AC_CONFIG_HEADERS([config.h])
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lldap_r':
AC_CHECK_LIB([ldap_r], [main])
AC_ARG_ENABLE([php], [  --enable-php	enable mod_php options],
		[php=${enableval}], [php=no])

if test "x${php}" = xyes; then
	PHP="-DWITH_PHP"
fi
AC_ARG_ENABLE([debug], [  --enable-debug   enable debugging symbols],
		[debug=${enableval}], [debug=no])

if test "x${debug}" = xyes; then
	DEBUG="-Wc,-g"
fi
AC_SUBST(PHP)
AC_SUBST(DEBUG)
# Checks for header files.
AC_CHECK_HEADERS([unistd.h])
# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp strchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
