#include "php_p7s.h"

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

/**
 *
 * /
int setSignedContent(PKCS7 * p7s, unsigned char ** signedContent) {
    ASN1_OCTET_STRING * octet_str;
    int length;
    unsigned char * contentString;
    unsigned char * contentStringEncoded;

    if (NULL == p7s->d.sign->contents->d.data) {
        return EXIT_FAILURE;
    }

    octet_str = p7s->d.sign->contents->d.data;
    length = octet_str->length;
    contentString = (unsigned char *) malloc(length);
    //signedContent = (unsigned char **) malloc(octet_str->length);
    //memset(signedContent, 0, octet_str->length);
    php_error(E_WARNING, "Oxi asd %s", octet_str->data);
    memcpy(contentString, octet_str->data, length);
    bin_to_strhex(octet_str->data, octet_str->length, signedContent);

    if (NULL == *signedContent) {
        return EXIT_FAILURE;
    }
    php_error(E_ERROR, "Oxi asd %s", contentStringEncoded);

    return EXIT_SUCCESS;
}

/**
 *
 * /
void setP7sSignatures(PKCS7 * p7s, zval ** signatures) {
    STACK_OF(PKCS7_SIGNER_INFO) * signerStack = PKCS7_get_signer_info(p7s);
    int numSignerInfo = sk_PKCS7_SIGNER_INFO_num(signerStack);

    int index;
    for (index = 0; index < numSignerInfo; ++index) {
        PKCS7_SIGNER_INFO * signerInfo = sk_PKCS7_SIGNER_INFO_value(signerStack, index);

        zval * signature;
        MAKE_STD_ZVAL(signature);
        array_init(signature);
        setP7sSignature(p7s, signerInfo, &signature);

        add_next_index_zval(*signatures, signature);
    }
}

/**
 *
 * /
void setP7sSignedContent(PKCS7 * p7s, zval ** signedContent) {
    ASN1_OCTET_STRING * octet_str;
    int length;
    unsigned char * contentString;
    unsigned char * contentStringEncoded;

    if (NULL == p7s->d.sign->contents->d.data) {
        ZVAL_STRING(*signedContent, "", 1);
        return;
    }

    octet_str = p7s->d.sign->contents->d.data;
    length = octet_str->length;
    contentString = (unsigned char *) malloc(length);
    memcpy(contentString, octet_str->data, length);
    bin_to_strhex(contentString, length, &contentStringEncoded);
    ZVAL_STRING(*signedContent, contentStringEncoded, 1);

    free(contentString);
    free(contentStringEncoded);
}

/**
 *
 * /
void setP7sSignature(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signature) {
    ASN1_TYPE * signedTime;
    zval * datetime;
    zval * param1;
    zval * param2;
    zval * signer;
    int type, index;
    long signerSerial;
    long signatureSerial;
    zend_class_entry * x509CE;

    signedTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
    
    MAKE_STD_ZVAL(param1);
    ZVAL_STRING(param1, "ymdHisZ", 1);

    MAKE_STD_ZVAL(param2);
    ZVAL_STRING(param2, signedTime->value.utctime->data, 1);

    if (zend_call_method(NULL, php_date_get_date_ce(), NULL, "createfromformat", strlen("createFromFormat"), &datetime, 2, param1, param2) == EXIT_FAILURE) {
        php_error(E_WARNING, "Could not create signature datetime.");
    }

    add_assoc_zval(*signature, "datetime", datetime);

    zval * x509Param;
    x509CE = php_openssl_pkcs_get_x509_ce();
    if (NULL == x509CE) {
        php_error(E_WARNING, "CE VAZIA");
    }

    MAKE_STD_ZVAL(signer);
    object_init_ex(signer, x509CE);

    STACK_OF(X509) * certs = NULL;
    type = OBJ_obj2nid(p7s->type);
    if (type == NID_pkcs7_signed) {
        certs = p7s->d.sign->cert;
    } else if(type == NID_pkcs7_signedAndEnveloped) {
        certs = p7s->d.signed_and_enveloped->cert;
    }
    FILE * file = fopen("/tmp/x509.pem", "w");
    if (NULL == file) {
        php_error(E_WARNING, "invalid file.");
        return;
    }
    signerSerial = ASN1_INTEGER_get(signerInfo->issuer_and_serial->serial);
    for (index = 0; certs && index < sk_X509_num(certs); index++) {
        X509 * x509 = sk_X509_value(certs,index);

        signatureSerial = ASN1_INTEGER_get(X509_get_serialNumber(x509));
        if (signerSerial != signatureSerial) {
            continue;
        }

        i2d_X509_fp(file, x509);
        MAKE_STD_ZVAL(x509Param);
        //ZVAL_STRING(x509Param, "/tmp/x509.pem", 1);
        ZVAL_STRING(x509Param, "/var/www/pkcs/certificate.crt", 1);

        if (zend_call_method(&signer, x509CE, &(x509CE)->constructor, ZEND_STRL(x509CE->constructor->common.function_name), NULL, 1, x509Param, NULL) == EXIT_FAILURE) {
            php_error(E_WARNING, "Could not create signer object.");
        }
        add_assoc_zval_ex(*signature, "signer", strlen("signer"), signer);
        break;
    }
    fclose(file);
}

/**
 *
 * /
void setSigner(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signer) {
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
        X509 * x509 = sk_X509_value(certs,index);

        signatureSerial = ASN1_INTEGER_get(X509_get_serialNumber(x509));
        if (signerSerial != signatureSerial) {
            continue;
        }
        setX509EntityData(x509, signer);
    }
}

/**
 *
 * /
void setX509EntityData(X509 * x509, zval ** entity) {
    X509_NAME * subjectName = X509_get_subject_name(x509);
    char serial[SERIAL_NUM_LEN + 1];
    int nid = OBJ_txt2nid("CN");
    int index = X509_NAME_get_index_by_NID(subjectName, nid, -1);
    X509_NAME_ENTRY * nameEntry = X509_NAME_get_entry(subjectName, index);

    getX509SerialNumber(x509, serial);

    add_assoc_string(*entity, "commonName", ASN1_STRING_data(X509_NAME_ENTRY_get_data(nameEntry)), 1);
    //add_assoc_long(*entity, "serialNumber", ASN1_INTEGER_get(X509_get_serialNumber(x509)));
    add_assoc_string(*entity, "serialNumber", serial, 1);
}

/**
 *
 * /
void getX509SerialNumber(X509 * x509, char * serialPtr) {
    
    ASN1_INTEGER *serial = X509_get_serialNumber(x509);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);

    if (!bn) {
        //printf(stderr, "unable to convert ASN1INTEGER to BN\n");
        //return EXIT_FAILURE;
    }
	
    char *tmp = BN_bn2dec(bn);
    if (!tmp) {
        //fprintf(stderr, "unable to convert BN to decimal string.\n");
        BN_free(bn);
        //return EXIT_FAILURE;
    }

    strncpy(serialPtr, tmp, SERIAL_NUM_LEN);
    BN_free(bn);
    OPENSSL_free(tmp);
}

/**/
