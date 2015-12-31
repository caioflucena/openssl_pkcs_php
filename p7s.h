#ifndef P7S_H_INCLUDED
#define P7S_H_INCLUDED

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

int getPkcs7FromFile(char * file, PKCS7 * p7s);
int getStackOfX509(PKCS7 * p7s, STACK_OF(X509) ** certs);
int getSignersInfo(PKCS7 * p7s, STACK_OF(PKCS7_SIGNER_INFO) ** signersInfo);
int getSignersInfoCount(STACK_OF(PKCS7_SIGNER_INFO) * signersStack, int * numSignerInfo);
int getSignerInfo(STACK_OF(PKCS7_SIGNER_INFO) * signersInfo, int * index, PKCS7_SIGNER_INFO ** signerInfo);
int getSignatureDatetimeString(PKCS7_SIGNER_INFO * p7ssignerInfo, unsigned char ** datetime);
int getSignatureX509(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, X509 ** x509);

#endif
