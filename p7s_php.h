#ifndef PHP_OPENSSL_PKCS_P7S_H
#define PHP_OPENSSL_PKCS_P7S_H

#include <php.h>
#include <zend_API.h>
#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include "ext/date/php_date.h"
#include "signer_info.h"
#include "x509_php.h"

/**
 *
 */
zend_class_entry * openssl_pkcs_p7s_ce;

/**
 *
 */
PHP_METHOD(openssl_pkcs_p7s, __construct);

/**
 *
 */
void openssl_pkcs_init_p7s(TSRMLS_D);

/**
 *
 */
void updatePropertyCertificates(void * object, PKCS7 * p7s);
void updatePropertySignatures(void * object, PKCS7 * p7s);
void updatePropertyIsDetached(void * object, int value);

#endif
