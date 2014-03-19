dnl $Id$
dnl config.m4 for extension ledu

AC_DEFUN([PHP_MCRYPT_CHECK_VERSION],[
  old_CPPFLAGS=$CPPFLAGS
  CPPFLAGS=-I$MCRYPT_DIR/include
  AC_MSG_CHECKING(for libmcrypt version)
  AC_EGREP_CPP(yes,[
#include <mcrypt.h>
#if MCRYPT_API_VERSION >= 20021217
  yes
#endif
  ],[
    AC_MSG_RESULT(>= 2.5.6)
  ],[
    AC_MSG_ERROR(libmcrypt version 2.5.6 or greater required.)
  ])
  CPPFLAGS=$old_CPPFLAGS
]) 

 PHP_ARG_WITH(ledu, for ledu support,
 [  --with-ledu=[=DIR]            Include ledu support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(ledu, whether to enable ledu support,
dnl Make sure that the comment is aligned:
dnl [  --enable-ledu           Enable ledu support])

if test "$PHP_LEDU" != "no"; then
  dnl Write more examples of tests here...
  for i in /usr/local /usr;do
     test -f $i/include/mcrypt.h && MCRYPT_DIR=$i && break
  done

  if test -z "$MCRYPT_DIR"; then
    AC_MSG_ERROR(mcrypt.h not found. Please reinstall libmcrypt.)
  fi

  PHP_MCRYPT_CHECK_VERSION
  
  PHP_CHECK_LIBRARY(mcrypt, mcrypt_module_open, 
  [
    PHP_ADD_LIBRARY(ltdl, LEDU_SHARED_LIBADD)
    AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])
  ],[
    PHP_CHECK_LIBRARY(mcrypt, mcrypt_module_open,
    [
      AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])
    ],[
      AC_MSG_ERROR([Sorry, I was not able to diagnose which libmcrypt version you have installed.])
    ],[
      -L$MCRYPT_DIR/$PHP_LIBDIR
    ])
  ],[
    -L$MCRYPT_DIR/$PHP_LIBDIR -lltdl
  ])
  PHP_ADD_LIBRARY_WITH_PATH(mcrypt, $MCRYPT_DIR/$PHP_LIBDIR, LEDU_SHARED_LIBADD)
  PHP_ADD_INCLUDE($MCRYPT_DIR/include)

  PHP_SUBST(LEDU_SHARED_LIBADD)
        
  
  PHP_NEW_EXTENSION(ledu, ledu.c, $ext_shared)
fi
