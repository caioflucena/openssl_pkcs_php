#ifndef X509_H_INCLUDED
#define X509_H_INCLUDED

/**
 *
 */
#include <php.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "ext/date/php_date.h"

/**
 *
 */
#define SERIAL_NUMBER_LENGTH 1000
#define SIGNATURE_ALGORITHM_LENGTH 1000
#define DATE_LENGTH 128

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
int getX509FromFile(char * file, X509 * x509);
int getVersion(X509 * x509, long * version);
int getSerialNumber(X509 * x509, char * serialNumber);
int getSignatureAlgorithm(X509 * x509, char * signatureAlgorithm);
int getValidityNotBefore(X509 * x509, char * validityNotBefore);
int getValidityNotAfter(X509 * x509, char * validityNotAfter);

#endif
