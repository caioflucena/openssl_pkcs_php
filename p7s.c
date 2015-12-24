#include "p7s.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_pkcs_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_pkcs_verify, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

PHP_METHOD(openssl_pkcs7, __construct) {
    int filenameLength;
    char * filename;
    FILE * file;
    PKCS7 * p7s = NULL;
    zval * signatures;
    zval * signedContent;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &filenameLength) == FAILURE) {
        return;
    }

    // cant find file
    file = fopen(filename, "r");
    if (NULL == file) {
        php_error(E_ERROR, "Invalid File.");
        return;
    } else {
        fclose(file);
    }

    // initialize openssl pkcs7
    if (!getPkcs7Bio(filename, &p7s) || NULL == p7s) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Invalid PKCS7 File.", 0 TSRMLS_CC);
        return;
    }

    // covering unexpected behaviours
    if (NULL == p7s) {
        php_error(E_ERROR, "Unexpected Error!");
        return;
    }

    // set signatures
    MAKE_STD_ZVAL(signatures);
    array_init(signatures);
    setP7sSignatures(p7s, &signatures);
    zend_update_property(openssl_pkcs_p7s_ce, getThis(), "signature", sizeof("signature")-1, signatures TSRMLS_CC);

    // set content info
    MAKE_STD_ZVAL(signedContent);
    setP7sSignedContent(p7s, &signedContent);
    zend_update_property(openssl_pkcs_p7s_ce, getThis(), "content", sizeof("content")-1, signedContent TSRMLS_CC);

    if (p7s != NULL) {
        PKCS7_free(p7s);
    }
}

/**
 *
 */
PHP_METHOD(openssl_pkcs7, getSignature) {
    zval * result;
           result = zend_read_property(openssl_pkcs_p7s_ce, getThis(), "signature", sizeof("signature")-1, 1 TSRMLS_CC);
    RETURN_ZVAL(result, 1, 0);
}

/**
 *
 */
PHP_METHOD(openssl_pkcs7, getContent) {
    zval * result;
           result = zend_read_property(openssl_pkcs_p7s_ce, getThis(), "content", sizeof("content")-1, 1 TSRMLS_CC);
    RETURN_ZVAL(result, 1, 0);
}

/**
 *
 */
PHP_METHOD(openssl_pkcs7, verify) {
    int filenameLength;
    char * filename;
    unsigned char * contentString;
    unsigned char * contentStringEncoded;
    FILE * file;
    zval * content;
    zval * result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &filenameLength) == FAILURE) {
        return;
    }
	
    file = fopen(filename, "rb");
    if (NULL == file) {
        php_error(E_WARNING, "invalid file.");
        return;
    } else {
        int length;

        fseek(file, 0L, SEEK_END);
        length = ftell(file);
        fseek(file, 0L, SEEK_SET);

        contentString = (unsigned char *) malloc(length);
        fread(contentString, length, 1, file); 
        bin_to_strhex(contentString, length, &contentStringEncoded);
        free(contentString);
    }
    fclose(file);

    content = zend_read_property(openssl_pkcs_p7s_ce, getThis(), "content", sizeof("content")-1, 1 TSRMLS_CC);
    if (NULL == content->value.str.val) {
        php_error(E_WARNING, "invalid content.");
        return;
    }

    MAKE_STD_ZVAL(result);
    if (strcmp(contentStringEncoded, content->value.str.val) == 0) {
        ZVAL_BOOL(result, 1);
    } else {
        ZVAL_BOOL(result, 0);
    }
    free(contentStringEncoded);

    RETURN_ZVAL(result, 1, 0);
}

/**
 * 
 */
static zend_function_entry openssl_pkcs_p7s_methods[] = {
    PHP_ME(openssl_pkcs7, __construct, arginfo_openssl_pkcs_construct, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    PHP_ME(openssl_pkcs7, getSignature, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    PHP_ME(openssl_pkcs7, getContent, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    PHP_ME(openssl_pkcs7, verify, arginfo_openssl_pkcs_verify, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

void openssl_pkcs_init_p7s(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\P7s", openssl_pkcs_p7s_methods);
    openssl_pkcs_p7s_ce = zend_register_internal_class(&ce TSRMLS_CC);
    // flags
    openssl_pkcs_p7s_ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
    // attributes
    zend_declare_property_null(openssl_pkcs_p7s_ce, "signature", sizeof("signature")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_p7s_ce, "content", sizeof("content")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
}

/**
 *
 */
int getPkcs7Bio(char * filename, PKCS7 ** p7s) {
    BIO * in = NULL;
          in = BIO_new(BIO_s_file());
    BIO_read_filename(in, filename);
    if (in == NULL) {
        return 0;
    }

    *p7s = d2i_PKCS7_bio(in, NULL);
    BIO_free(in);

    if (NULL ==  p7s) {
        return 0;
    }

    return 1;
}

/**
 *
 */
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
 */
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
 */
void setP7sSignature(PKCS7 * p7s, PKCS7_SIGNER_INFO * signerInfo, zval ** signature) {
    ASN1_TYPE * signedTime;
    zval * datetime;
    zval * param1;
    zval * param2;
    zval * signer;
    TSRMLS_FETCH();

    signedTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
    
    MAKE_STD_ZVAL(param1);
    ZVAL_STRING(param1, "ymdHisZ", 1);

    MAKE_STD_ZVAL(param2);
    ZVAL_STRING(param2, signedTime->value.utctime->data, 1);

    if (zend_call_method(NULL, php_date_get_date_ce(), NULL, "createfromformat", strlen("createFromFormat"), &datetime, 2, param1, param2 TSRMLS_CC) == NULL) {
        php_error(E_WARNING, "Could not create signature datetime.");
    }

    add_assoc_zval(*signature, "datetime", datetime);

    // signer issuer
    MAKE_STD_ZVAL(signer);
    array_init(signer);
    setSigner(p7s, signerInfo, &signer);
    add_assoc_zval(*signature, "signer", signer);
}

/**
 *
 */
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
 */
void setX509EntityData(X509 * x509, zval ** entity) {
    X509_NAME * subjectName = X509_get_subject_name(x509);
    char serial[SERIAL_NUM_LEN + 1];
    int nid = OBJ_txt2nid("CN");
    TSRMLS_FETCH();

    int index = X509_NAME_get_index_by_NID(subjectName, nid, -1);
    X509_NAME_ENTRY * nameEntry = X509_NAME_get_entry(subjectName, index);

    add_assoc_string(*entity, "commonName", ASN1_STRING_data(X509_NAME_ENTRY_get_data(nameEntry)), 1);

    getX509SerialNumber(x509, serial);
    add_assoc_string(*entity, "serialNumber", serial, 1);

    zend_class_entry * dateTimeCE = php_date_get_date_ce();
    char * validityNotBefore = (char *)malloc(sizeof(char)*128);
    zval * validityNotBeforeAttribute;
    zval * validityNotBeforeDateParam;
    ASN1_TIME *not_before = X509_get_notBefore(x509);
    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, not_before);
    if (rc <= 0) {
        BIO_free(b);
        php_error(E_ERROR, "Could not read X509 validity not before.");
    }
    rc = BIO_gets(b, validityNotBefore, 128);
    if (rc <= 0) {
        BIO_free(b);
        php_error(E_ERROR, "Could not read X509 validity not before.");
    }
    BIO_free(b);
    MAKE_STD_ZVAL(validityNotBeforeAttribute);
    object_init_ex(validityNotBeforeAttribute, dateTimeCE);
    MAKE_STD_ZVAL(validityNotBeforeDateParam);
    ZVAL_STRING(validityNotBeforeDateParam, validityNotBefore, 1);
    free(validityNotBefore);
    add_assoc_zval(*entity, "validityNotBefore", validityNotBeforeDateParam);
    //if (zend_call_method(&validityNotBeforeAttribute, dateTimeCE, &dateTimeCE->constructor, ZEND_STRL(&dateTimeCE->constructor->common.function_name), NULL, 1, validityNotBeforeDateParam TSRMLS_CC) == EXIT_FAILURE) {
    //    php_error(E_WARNING, "Could not create validity not before datetime object.");
    //}
    //add_assoc_zval(*entity, "validityNotBefore", validityNotBeforeDateParam);

    char * validityNotAfter = (char *)malloc(sizeof(char)*128);
    zval * validityNotAfterAttribute;
    zval * validityNotAfterDateParam;
    ASN1_TIME *not_after = X509_get_notAfter(x509);
    BIO *c = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(c, not_before);
    if (rc <= 0) {
        BIO_free(c);
        php_error(E_ERROR, "Could not read X509 validity not before.");
    }
    rc = BIO_gets(c, validityNotAfter, 128);
    if (rc <= 0) {
        BIO_free(c);
        php_error(E_ERROR, "Could not read X509 validity not before.");
    }
    BIO_free(c);
    MAKE_STD_ZVAL(validityNotAfterAttribute);
    object_init_ex(validityNotAfterAttribute, dateTimeCE);
    MAKE_STD_ZVAL(validityNotAfterDateParam);
    ZVAL_STRING(validityNotAfterDateParam, validityNotAfter, 1);
    free(validityNotAfter);
    add_assoc_zval(*entity, "validityNotAfter", validityNotAfterDateParam);
}

/**
 *
 */
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

    /*
    if (strlen(tmp) >= len) {
        //fprintf(stderr, "buffer length shorter than serial number\n");
        BN_free(bn);
        OPENSSL_free(tmp);
        //return EXIT_FAILURE;
    }
    */

    strncpy(serialPtr, tmp, SERIAL_NUM_LEN);
    BN_free(bn);
    OPENSSL_free(tmp);
}

/**
 *
 */
void bin_to_strhex(unsigned char *bin, unsigned int binsz, unsigned char **result) {
    char hex_str[]= "0123456789abcdef";
    unsigned int  i;

    * result = (char *)malloc(binsz * 2 + 1);
    (* result)[binsz * 2] = 0;

    if (!binsz) {
        return;
    }

    for (i = 0; i < binsz; i++) {
        (* result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        (* result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }  
}

