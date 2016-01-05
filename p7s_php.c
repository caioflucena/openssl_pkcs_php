#include "p7s_php.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_pkcs_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_pkcs_verify, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

PHP_METHOD(openssl_pkcs_p7s, __construct) {
    int filenameLength = 0;
    char * filename = NULL;
    PKCS7 * p7s = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &filenameLength) == FAILURE) {
        return;
    }

    BIO * bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filename);
    if (bio == NULL) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read p7s file.", 0 TSRMLS_CC);
        return;
    }
    d2i_PKCS7_bio(bio, &p7s);
    if (NULL == p7s) {
        PKCS7_free(p7s);
        BIO_free(bio);
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read p7s file.", 0 TSRMLS_CC);
        return;
    }
    BIO_free(bio);

    char * type = malloc(1000*sizeof(char));
    *type = 0x0;
    int nid = OBJ_obj2nid(p7s->type);
    if (-1 < nid) {
        const char* sslbuf = OBJ_nid2ln(nid);
        strncpy(type, sslbuf, 1000*sizeof(char));
    }
    zval * typeAttribute;
    MAKE_STD_ZVAL(typeAttribute);
    ZVAL_STRING(typeAttribute, type, 1);
    zend_update_property(openssl_pkcs_p7s_ce, getThis(), "type", strlen("type"), typeAttribute TSRMLS_CC);
    free(type);

    // data
    //zval * data;
    //MAKE_STD_ZVAL(data);
    //ZVAL_STRING(data, p7s->d.data->data, 1);
    //zend_update_property(openssl_pkcs_p7s_ce, getThis(), "data", sizeof("data")-1, data TSRMLS_CC);

    // signed
    zend_class_entry * signedCE = php_openssl_pkcs_get_signed_ce();
    zval * signedInstance;
    MAKE_STD_ZVAL(signedInstance);
    object_init_ex(signedInstance, signedCE);

    zval * signedParam;
    MAKE_STD_ZVAL(signedParam);
    int resourceID;
        resourceID = ZEND_REGISTER_RESOURCE(signedParam, p7s->d.sign, le_openssl_signed_resource);
    if (zend_call_method(&signedInstance, signedCE, &(signedCE)->constructor, ZEND_STRL(signedCE->constructor->common.function_name), NULL, 1, signedParam, NULL) == EXIT_FAILURE) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create a signer info instance.", 0 TSRMLS_CC);
        return;
    }
    zend_update_property(openssl_pkcs_p7s_ce, getThis(), "signed", strlen("signed"), signedInstance TSRMLS_CC);

    // attributes
    //updatePropertySignatures(getThis(), p7s);
    //updatePropertyCertificates(getThis(), p7s);

    free(p7s);
}

/**
 *
 * /
PHP_METHOD(openssl_pkcs7, getSignature) {
    zval * result;
           result = zend_read_property(openssl_pkcs_p7s_ce, getThis(), "signature", sizeof("signature")-1, 1 TSRMLS_CC);
    RETURN_ZVAL(result, 1, 0);
}

/**
 *
 * /
PHP_METHOD(openssl_pkcs7, getContent) {
    zval * result;
           result = zend_read_property(openssl_pkcs_p7s_ce, getThis(), "content", sizeof("content")-1, 1 TSRMLS_CC);
    RETURN_ZVAL(result, 1, 0);
}

/**
 *
 * /
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
    PHP_ME(openssl_pkcs_p7s, __construct, arginfo_openssl_pkcs_construct, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    //PHP_ME(openssl_pkcs7, getSignature, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    //PHP_ME(openssl_pkcs7, getContent, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    //PHP_ME(openssl_pkcs7, verify, arginfo_openssl_pkcs_verify, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

void openssl_pkcs_init_p7s(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\P7s", openssl_pkcs_p7s_methods);
    openssl_pkcs_p7s_ce = zend_register_internal_class(&ce TSRMLS_CC);
    // flags
    openssl_pkcs_p7s_ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
    // attributes
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "signatures", sizeof("signatures")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "certificates", sizeof("certificates")-1, ZEND_ACC_PRIVATE TSRMLS_CC);

    zend_declare_property_null(openssl_pkcs_p7s_ce, "type", strlen("type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "data", sizeof("data")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_p7s_ce, "signed", strlen("signed"), ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "enveloped", sizeof("enveloped")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "signed_and_enveloped", sizeof("signed_and_enveloped")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "digest", sizeof("digest")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "encrypted", sizeof("encrypted")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
    //zend_declare_property_null(openssl_pkcs_p7s_ce, "other", sizeof("other")-1, ZEND_ACC_PRIVATE TSRMLS_CC);
}

/**
 *
 */
void updatePropertyCertificates(void * object, PKCS7 * p7s) {
    zend_class_entry * x509CE = php_openssl_pkcs_get_x509_ce();
    STACK_OF(X509) * certificates;
    zval * certificatesAttribute;

    int type;
    type = OBJ_obj2nid(p7s->type);
    if (type == NID_pkcs7_signed) {
        certificates = p7s->d.sign->cert;
    } else if(type == NID_pkcs7_signedAndEnveloped) {
        certificates = p7s->d.signed_and_enveloped->cert;
    }

    MAKE_STD_ZVAL(certificatesAttribute);
    array_init(certificatesAttribute);

    int i;
    for (i = 0; certificates && i < sk_X509_num(certificates); i++) {
        X509 * x509 = sk_X509_value(certificates, i);

        zval * certificate;
        MAKE_STD_ZVAL(certificate);
        object_init_ex(certificate, x509CE);

        zval * x509Param;
        MAKE_STD_ZVAL(x509Param);

        zval * fileParam;
        MAKE_STD_ZVAL(fileParam);
        ZVAL_STRING(fileParam, "", 1);

        int resourceID;
        resourceID = ZEND_REGISTER_RESOURCE(x509Param, x509, le_openssl_x509_resource);

        if (zend_call_method(&certificate, x509CE, &(x509CE)->constructor, ZEND_STRL(x509CE->constructor->common.function_name), NULL, 2, fileParam, x509Param) == EXIT_FAILURE) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create certificate instance.", 0 TSRMLS_CC);
            return;
        }
        add_next_index_zval(certificatesAttribute, certificate);
    }

    zend_update_property(openssl_pkcs_p7s_ce, object, "certificates", sizeof("certificates")-1, certificatesAttribute TSRMLS_CC);
}

void updatePropertySignatures(void * object, PKCS7 * p7s) {
    int index;
    int numSignerInfo;
    STACK_OF(PKCS7_SIGNER_INFO) * p7sSignersInfo;
    PKCS7_SIGNER_INFO * p7sSignerInfo;
    zval * signatures;
    zval * signature;
    zval * signatureDatetime;
    zval * signatureSigner;

    MAKE_STD_ZVAL(signatures);
    array_init(signatures);

    p7sSignersInfo = PKCS7_get_signer_info(p7s);
    numSignerInfo = sk_PKCS7_SIGNER_INFO_num(p7sSignersInfo);

    for (index = 0; index < numSignerInfo; ++index) {
        p7sSignerInfo = sk_PKCS7_SIGNER_INFO_value(p7sSignersInfo, index);

        MAKE_STD_ZVAL(signature);
        array_init(signature);

        unsigned char * datetime = NULL;
        zval * param1;
        zval * param2;
        ASN1_TYPE * signedTime = PKCS7_get_signed_attribute(p7sSignerInfo, NID_pkcs9_signingTime);
        if (NULL == signedTime) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create signature datetime instance.", 0 TSRMLS_CC);
            return;
        }
        datetime = signedTime->value.utctime->data;
        if (NULL == datetime) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create signature datetime instance.", 0 TSRMLS_CC);
            return;
        }
        MAKE_STD_ZVAL(param1);
        ZVAL_STRING(param1, "ymdHisZ", 1);
        MAKE_STD_ZVAL(param2);
        ZVAL_STRING(param2, datetime, 1);
        if (zend_call_method(NULL, php_date_get_date_ce(), NULL, "createfromformat", strlen("createFromFormat"), &signatureDatetime, 2, param1, param2 TSRMLS_CC) == NULL) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create signature datetime instance.", 0 TSRMLS_CC);
            return;
        }

        add_assoc_zval(signature, "datetime", signatureDatetime);

        add_next_index_zval(signatures, signature);
    }

    zend_update_property(openssl_pkcs_p7s_ce, object, "signatures", sizeof("signatures")-1, signatures TSRMLS_CC);
}

void updatePropertyIsDetached(void * object, int value) {
    zval * isDetachedAttribute;
    MAKE_STD_ZVAL(isDetachedAttribute);
    ZVAL_BOOL(isDetachedAttribute, value);
    zend_update_property(openssl_pkcs_p7s_ce, object, "isDetached", sizeof("isDetached")-1, isDetachedAttribute);
}
