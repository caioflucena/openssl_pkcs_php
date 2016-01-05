#ifndef PHP_OPENSSL_PKCS_SIGNER_INFO_H
#define PHP_OPENSSL_PKCS_SIGNER_INFO_H

#include <string.h>
#include <php.h>
#include <zend_API.h>
#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include "ext/date/php_date.h"

/**
 *
 */
#define PHP_OPENSSL_PKCS_SIGNER_INFO_RESOURCE_NAME "SingerInfo Data"

/**
 *
 */
zend_class_entry * openssl_pkcs_signer_info_ce;
static int le_openssl_signer_info_resource;

/**
 *
 */
PHP_METHOD(openssl_pkcs_signer_info, __construct);

/**
 *
 */
PHPAPI zend_class_entry * php_openssl_pkcs_get_signer_info_ce(void);
void openssl_pkcs_init_signer_info(TSRMLS_D);

#endif
