dnl $Id$
PHP_ARG_WITH(openssl_pkcs, for openssl_pkcs support, [  --with-openssl_pkcs             Include openssl_pkcs support])

if test "$PHP_OPENSSL_PKCS" != "no"; then
  PHP_NEW_EXTENSION(openssl_pkcs, openssl_pkcs.c, $ext_shared)
fi
