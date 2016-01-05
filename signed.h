#ifndef PHP_OPENSSL_PKCS_SIGNED_H
#define PHP_OPENSSL_PKCS_SIGNED_H

#include <php.h>
#include <zend_API.h>
#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include "signer_info.h"
#include "x509_php.h"

/**
 *
 */
#define PHP_OPENSSL_PKCS_SIGNED_RESOURCE_NAME "Singed Data"

/**
 *
 */
zend_class_entry * openssl_pkcs_signed_ce;
static int le_openssl_signed_resource;

/**
 *
 */
PHP_METHOD(openssl_pkcs_signed, __construct);

/**
 *
 */
PHPAPI zend_class_entry * php_openssl_pkcs_get_signed_ce(void);
void openssl_pkcs_init_signed(TSRMLS_D);

#endif
