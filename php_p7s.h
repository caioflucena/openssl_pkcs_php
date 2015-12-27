#ifndef PHP_OPENSSL_PKCS_P7S_H
#define PHP_OPENSSL_PKCS_P7S_H

#include <zend_API.h>
#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include <php.h>
#include "ext/date/php_date.h"
#include "p7s.h"
#include "php_x509.h"

zend_class_entry * openssl_pkcs_p7s_ce;

void openssl_pkcs_init_p7s(TSRMLS_D);

PHP_METHOD(openssl_pkcs, __construct);

/**
 *
 */
void updatePropertySignatures(void * object, PKCS7 * p7s);
void updatePropertyIsDetached(void * object, int value);

/**
 *
 */
int getSignatureDatetime(PKCS7_SIGNER_INFO * p7ssignerInfo, zval ** signatureDatetime);
int getSignatureSigner(PKCS7_SIGNER_INFO * p7sSignerInfo, zval ** signatureSigner);

#endif	/* PHP_OPENSSL_PKCS_P7S_H */
