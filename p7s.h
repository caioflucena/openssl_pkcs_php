#ifndef P7S_H_INCLUDED
#define P7S_H_INCLUDED

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

//#define SERIAL_NUM_LEN 1000

int getPkcs7FromFile(char * file, PKCS7 * p7s);
int getSignersInfo(PKCS7 * p7s, STACK_OF(PKCS7_SIGNER_INFO) ** signersInfo);
int getSignersInfoCount(STACK_OF(PKCS7_SIGNER_INFO) * signersStack, int * numSignerInfo);
int getSignerInfo(STACK_OF(PKCS7_SIGNER_INFO) * signersInfo, int * index, PKCS7_SIGNER_INFO ** signerInfo);
int getSignatureDatetimeString(PKCS7_SIGNER_INFO * p7ssignerInfo, unsigned char ** datetime);
int getSignatureX509(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, X509 ** x509);
//int setSignedContent(PKCS7 * p7s, unsigned char ** signedContent);

/*
void setP7sSignatures(PKCS7 * p7s, zval ** signatures);
void setP7sSignedContent(PKCS7 * p7s, zval ** signedContent);
void setP7sSignature(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signature);
void setSigner(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signer);
void setX509EntityData(X509 * x509, zval ** entity);
void bin_to_strhex(unsigned char *bin, unsigned int binsz, unsigned char **result);
void getX509SerialNumber(X509 * x509, char * serialPtr);
*/

#endif
