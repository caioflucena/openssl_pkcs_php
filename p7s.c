#include <php.h>
#include "p7s.h"

PHP_METHOD(ikhon_pkcs7, __construct) {
    int filenameLength;
    char * filename;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &filenameLength) == FAILURE) {
        return;
    }

    // cant find file
    FILE * file;
           file = fopen(filename, "r");
    if (NULL == file) {
        php_error(E_WARNING, "invalid file.");
        return;
    } else {
        fclose(file);
    }

    // initialize openssl pkcs7
    PKCS7 * p7s = NULL;
    if (!getPkcs7Bio(filename, &p7s)) {
        php_error(E_WARNING, "invalid pkcs7 file.");
        return;
    }

    // covering unexpected behaviours
    if (NULL == p7s) {
        php_error(E_WARNING, "unexpected error!");
        return;
    }

    // set signatures
    zval * signatures;
    MAKE_STD_ZVAL(signatures);
    array_init(signatures);
    setP7sSignatures(p7s, &signatures);

    // class attributes
    zend_update_property(openssl_pkcs_p7s_ce, getThis(), "signatures", sizeof("signatures"), signatures TSRMLS_CC);
    //zend_update_property(ikhon_pkcs7_ce, getThis(), "content", sizeof("content"), signedContent TSRMLS_CC);

    if (p7s != NULL) {
        PKCS7_free(p7s);
    }
}

/**
 *  *
 *   */
static zend_function_entry openssl_pkcs_p7s_methods[] = {
    PHP_ME(ikhon_pkcs7, __construct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    //PHP_ME(ikhon_pkcs7, __destruct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    //PHP_ME(ikhon_pkcs7, getSignatures, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    //PHP_ME(ikhon_pkcs7, getSignedContent, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

void openssl_pkcs_init_p7s(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\P7s", openssl_pkcs_p7s_methods);
    openssl_pkcs_p7s_ce = zend_register_internal_class(&ce TSRMLS_CC);
    //openssl_pkcs_p7s_ce->create_object = ikhon_pkcs7_create_object;
    //memcpy(&ikhon_pkcs7_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
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
setP7sSignatures(PKCS7 * p7s, zval ** signatures) {
    STACK_OF(PKCS7_SIGNER_INFO) * signerStack = PKCS7_get_signer_info(p7s);
    int numSignerInfo = sk_PKCS7_SIGNER_INFO_num(signerStack);

    int index;
    for (index = 0; index < numSignerInfo; ++index) {
        PKCS7_SIGNER_INFO * signerInfo = sk_PKCS7_SIGNER_INFO_value(signerStack, index);

        zval * signature;
        MAKE_STD_ZVAL(signature);
        array_init(signature);
        setP7sSignature(signerInfo, &signature);

        add_next_index_zval(*signatures, signature);
    }
}

/**
 *
 */
setP7sSignature(PKCS7_SIGNER_INFO * signerInfo, zval ** signature) {
    // sign time
    ASN1_TYPE * signedTime;
                signedTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
    zval * datetime;
    zval * param1;
    MAKE_STD_ZVAL(param1);
    ZVAL_STRING(param1, "ymdHisZ", 1);

    zval * param2;
    MAKE_STD_ZVAL(param2);
    ZVAL_STRING(param2, signedTime->value.utctime->data, 1);

    if (zend_call_method(NULL, php_date_get_date_ce(), NULL, "createfromformat", strlen("createFromFormat"), &datetime, 2, param1, param2 TSRMLS_CC ) == FAILURE) {
        php_error(E_WARNING, "Could not create signature datetime.");
    }

    add_assoc_zval(*signature, "datetime", datetime);

    // signer issuer
    zval * signer;

    STACK_OF(X509) * x509s = NULL;
                     x509s = getStackX509(p7s);
    int index;
    for (index = 0; x509s && index < sk_X509_num(x509s); index++) {

        X509 * x509 = sk_X509_value(x509s,index);
        zval * data = getData(x509);

        long x509Serial = ASN1_INTEGER_get(X509_get_serialNumber(x509));

        if (x509Serial == serial) {
            signer = getSubject(x509);

            //printf("\n---------------------------------------------------------------------------\n");
            //printf("Cert #%d\n", index);
            //X509_print_fp(stdout, x509);
        }
    }
    add_assoc_zval(signature, "signer", getSignerBySerial(p7s, ASN1_INTEGER_get(signerInfo->issuer_and_serial->serial)));
}

