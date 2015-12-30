#ifndef X509_H_INCLUDED
#define X509_H_INCLUDED

/**
 *
 */
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/**
 *
 */
#define SERIAL_NUMBER_LENGTH 1000
#define SIGNATURE_ALGORITHM_LENGTH 1000
#define DATE_LENGTH 128
#define ISSUER_LENGTH 1000
#define SUBJECT_LENGTH 1000

/**
 *
 */
int getX509FromFile(char * file, X509 * x509);
int getVersion(X509 * x509, long * version);
int getSerialNumber(X509 * x509, char * serialNumber);
int getSignatureAlgorithm(X509 * x509, char * signatureAlgorithm);
int getValidityNotBefore(X509 * x509, char * validityNotBefore);
int getValidityNotAfter(X509 * x509, char * validityNotAfter);
int getIssuer(X509 * x509, char * issuer);
int getSubject(X509 * x509, char * subject);

#endif
