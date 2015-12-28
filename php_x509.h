#ifndef PHP_OPENSSL_PKCS_H
#define PHP_OPENSSL_PKCS_H

#include <zend_API.h>
#include <zend_exceptions.h>
#include "x509.h"

extern zend_module_entry openssl_pkcs_module_entry;
X509 * RESOURCE_X509;

/**
 * 
 */
zend_class_entry * openssl_pkcs_x509_ce;

/**
 * 
 */
void openssl_pkcs_init_x509(TSRMLS_D);

/**
 * 
 */
PHP_METHOD(openssl_pkcs_x509, __construct);

/**
 *
 */
PHPAPI zend_class_entry * php_openssl_pkcs_get_x509_ce(void);

/**
 *
 */
#define phpext_openssl_pkcs_ptr &openssl_pkcs_module_entry
#define PHP_OPENSSL_PKCS_VERSION "0.1.0" /* Replace with version number for your extension */

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

#endif	/* PHP_OPENSSL_PKCS_H */
