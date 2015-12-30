#ifndef PHP_OPENSSL_PKCS_X509_H
#define PHP_OPENSSL_PKCS_X509_H

#include <php.h>
#include <zend_API.h>
#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include "ext/date/php_date.h"
#include "x509.h"

/**
 *
 */
#define PHP_OPENSSL_PKCS_X509_RESOURCE_NAME "X509 Data"
#define PHP_OPENSSL_PKCS_X509_ISSUER "ISSUER"
#define PHP_OPENSSL_PKCS_X509_SUBJECT "SUBJECT"

/**
 * 
 */
zend_class_entry * openssl_pkcs_x509_ce;
static int le_openssl_x509_resource;

/**
 * 
 */
PHP_METHOD(openssl_pkcs_x509, __construct);

/**
 *
 */
PHPAPI zend_class_entry * php_openssl_pkcs_get_x509_ce(void);
void openssl_pkcs_init_x509(TSRMLS_D);

/**
 *
 */
void updatePropertyVersion(void * object, X509 * x509);
void updatePropertySerialNumber(void * object, X509 * x509);
void updatePropertyValidity(void * object, X509 * x509);
void updatePropertyIssuerSubject(void * object, X509 * x509, char * type);
void updatePropertySubjectPublicKeyInfo(void * object, X509 * x509);

#endif
