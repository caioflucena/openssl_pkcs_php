#include "p7s_php.h"

/**
 *
 */
int getPkcs7FromFile(char * file, PKCS7 * p7s) {
    BIO * bio = NULL;
          bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, file);
    if (bio == NULL) {
        BIO_free(bio);
        return EXIT_FAILURE;
    }

    PKCS7 * out = d2i_PKCS7_bio(bio, NULL);
    if (NULL == out) {
        BIO_free(bio);
        return EXIT_FAILURE;
    }
    memcpy(p7s, out, sizeof(PKCS7));
    if (NULL == p7s) {
        PKCS7_free(out);
        BIO_free(bio);
        return EXIT_FAILURE;
    }

    //PKCS7_free(out);
    BIO_free(bio);
    return EXIT_SUCCESS;
}

int getStackOfX509(PKCS7 * p7s, STACK_OF(X509) ** certs) {
    int type;
    type = OBJ_obj2nid(p7s->type);
    if (type == NID_pkcs7_signed) {
        *certs = p7s->d.sign->cert;
    } else if(type == NID_pkcs7_signedAndEnveloped) {
        *certs = p7s->d.signed_and_enveloped->cert;
    }

    if (NULL == certs) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int getSignersInfo(PKCS7 * p7s, STACK_OF(PKCS7_SIGNER_INFO) ** signersInfo) {
    *signersInfo = PKCS7_get_signer_info(p7s);
    if (NULL == signersInfo) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int getSignersInfoCount(STACK_OF(PKCS7_SIGNER_INFO) * signersInfo, int * numSignerInfo) {
    *numSignerInfo = sk_PKCS7_SIGNER_INFO_num(signersInfo);
    if (NULL == numSignerInfo || -1 == *numSignerInfo) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int getSignerInfo(STACK_OF(PKCS7_SIGNER_INFO) * signersInfo, int * index, PKCS7_SIGNER_INFO ** signerInfo) {
    *signerInfo = sk_PKCS7_SIGNER_INFO_value(signersInfo, *index);
    if (NULL == signerInfo) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int getSignatureDatetimeString(PKCS7_SIGNER_INFO * signerInfo, unsigned char ** datetime) {
    ASN1_TYPE * signedTime;

    signedTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
    if (NULL == signedTime) {
        return EXIT_FAILURE;
    }
    *datetime = signedTime->value.utctime->data;
    if (NULL == datetime) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int getSignatureX509(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, X509 ** x509) {
    STACK_OF(X509) * certs = NULL;
    long signerSerial;
    long signatureSerial;
    int type;
    int index;
    signerSerial = ASN1_INTEGER_get(signerInfo->issuer_and_serial->serial);
    type = OBJ_obj2nid(p7s->type);
    if (type == NID_pkcs7_signed) {
        certs = p7s->d.sign->cert;
    } else if(type == NID_pkcs7_signedAndEnveloped) {
        certs = p7s->d.signed_and_enveloped->cert;
    }
    for (index = 0; certs && index < sk_X509_num(certs); index++) {
        X509 * out = sk_X509_value(certs,index);
        signatureSerial = ASN1_INTEGER_get(X509_get_serialNumber(*x509));
        if (signerSerial != signatureSerial) {
            continue;
        }
        *x509 = out;
    }

    if (NULL == x509) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
