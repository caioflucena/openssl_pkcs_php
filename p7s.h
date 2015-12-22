#ifndef P7S_H_INCLUDED
#define P7S_H_INCLUDED

#include <zend_interfaces.h>
#include <zend_exceptions.h>
#include <php.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include "ext/date/php_date.h"

#define SERIAL_NUM_LEN 1000

zend_class_entry * openssl_pkcs_p7s_ce;

static zend_object_handlers ikhon_pkcs7_object_handlers;

void openssl_pkcs_init_p7s(TSRMLS_D);

PHP_METHOD(openssl_pkcs_p7s, __construct);

/** /
typedef struct _ikhon_pkcs7_struct {
    zend_object std;
    zval * signatures;
    int contentLength;
    unsigned char * content;
} openssl_pkcs_p7s_object;

/** /
zval * getCerts(PKCS7 * p7s);
zval * getSignerBySerial(PKCS7 * p7s, long serial);
zval * getSignatures(PKCS7 * p7s);
PKCS7 * getPkcs7Bio(char * filename);
STACK_OF(X509) * getStackX509(PKCS7 * p7s);

char * getSignatureAlgorithm(X509 * x509);
zval * getData(X509 * x509);
zval * getValidity(X509 * x509);
zval * getIssuer(X509 * x509);
zval * getSubject(X509 * x509);
/**/

//zval * getSignatures(PKCS7 * p7s);

int getPkcs7Bio(char * filepath, PKCS7 ** p7s);
void setP7sSignatures(PKCS7 * p7s, zval ** signatures);
void setP7sSignedContent(PKCS7 * p7s, zval ** signedContent);
void setP7sSignature(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signature);
void setSigner(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signer);
void setX509EntityData(X509 * x509, zval ** entity);
void bin_to_strhex(unsigned char *bin, unsigned int binsz, unsigned char **result);
void getX509SerialNumber(X509 * x509, char * serialPtr);

#endif
