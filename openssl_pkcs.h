#ifndef PHP_OPENSSL_PKCS_H
#define PHP_OPENSSL_PKCS_H

#include "p7s_php.h"
#include "signer_info.h"
#include "x509_php.h"

extern zend_module_entry openssl_pkcs_module_entry;

#define phpext_openssl_pkcs_ptr &openssl_pkcs_module_entry
#define PHP_OPENSSL_PKCS_VERSION "0.1.0"

#ifdef PHP_WIN32
#	define PHP_OPENSSL_PKCS_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_OPENSSL_PKCS_API __attribute__ ((visibility("default")))
#else
#	define PHP_OPENSSL_PKCS_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#ifdef ZTS
#define OPENSSL_PKCS_G(v) TSRMG(openssl_pkcs_globals_id, zend_openssl_pkcs_globals *, v)
#else
#define OPENSSL_PKCS_G(v) (openssl_pkcs_globals.v)
#endif

#endif
