#include "signer_info.h"

PHP_METHOD(openssl_pkcs_signer_info, __construct) {
    zval * signerInfoParam;
    PKCS7_SIGNER_INFO * signerInfo;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|r", &signerInfoParam) == FAILURE) {
        return;
    }

    ZEND_FETCH_RESOURCE(signerInfo, PKCS7_SIGNER_INFO*, &signerInfoParam, -1, PHP_OPENSSL_PKCS_SIGNER_INFO_RESOURCE_NAME, le_openssl_signer_info_resource);

    if (NULL == signerInfo || NULL == signerInfo->issuer_and_serial) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read signer info resource.", 0 TSRMLS_CC);
        return;
    }

    //zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "resource", strlen("resource"), signerInfoParam);

    char * buff = malloc(1000*sizeof(char));
    *buff = 0x0;
    X509_NAME_oneline(signerInfo->issuer_and_serial->issuer, buff, 1000*sizeof(char));
    zval * issuer;
    MAKE_STD_ZVAL(issuer);
    ZVAL_STRING(issuer, buff, 1);
    zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "issuer", strlen("issuer"), issuer);
    free(buff);

    unsigned char * serialNumber = malloc(1000*sizeof(char));
    BIGNUM *bn = ASN1_INTEGER_to_BN(signerInfo->issuer_and_serial->serial, NULL);
    serialNumber = BN_bn2dec(bn);
    BN_free(bn);
    zval * serialNumberAttribute;
    MAKE_STD_ZVAL(serialNumberAttribute);
    ZVAL_STRING(serialNumberAttribute, serialNumber, 1);
    zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "serialNumber", strlen("serialNumber"), serialNumberAttribute);
    free(serialNumber);

    int nid;

    nid = OBJ_obj2nid(signerInfo->digest_alg->algorithm);
    unsigned char * digestAlgorithm = malloc(1000*sizeof(char));
    *digestAlgorithm = 0x0;
    if (-1 < nid) {
        const char* sslbuf = OBJ_nid2ln(nid);
        strncpy(digestAlgorithm, sslbuf, 1000*sizeof(char));
    }
    zval * digestAlgorithmAttribute;
    MAKE_STD_ZVAL(digestAlgorithmAttribute);
    ZVAL_STRING(digestAlgorithmAttribute, digestAlgorithm, 1);
    zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "digestAlgorithm", strlen("digestAlgorithm"), digestAlgorithmAttribute);
    free(digestAlgorithm);

    nid = OBJ_obj2nid(signerInfo->digest_enc_alg->algorithm);
    unsigned char * digestEncryptAlgorithm = malloc(1000*sizeof(char));
    *digestEncryptAlgorithm = 0x0;
    if (-1 < nid) {
        const char* sslbuf = OBJ_nid2ln(nid);
        strncpy(digestEncryptAlgorithm, sslbuf, 1000*sizeof(char));
    }
    zval * digestEncryptAlgorithmAttribute;
    MAKE_STD_ZVAL(digestEncryptAlgorithmAttribute);
    ZVAL_STRING(digestEncryptAlgorithmAttribute, digestEncryptAlgorithm, 1);
    zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "digestEncryptAlgorithm", strlen("digestEncryptAlgorithm"), digestEncryptAlgorithmAttribute);
    free(digestEncryptAlgorithm);

    // @todo
    //add_assoc_string(signature, "enc_digest", ASN1_STRING_data(p7sSignerInfo->enc_digest), 1);

    zval * signatureDatetime;
    unsigned char * datetime = NULL;
    zval * param1;
    zval * param2;
    ASN1_TYPE * signedTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
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
    zend_update_property(openssl_pkcs_signer_info_ce, getThis(), "signingTime", strlen("signingTime"), signatureDatetime);
}

/**
 *
 */
zend_class_entry * php_openssl_pkcs_get_signer_info_ce(void) {
    return openssl_pkcs_signer_info_ce;
}

/**
 *
 */
static zend_function_entry openssl_pkcs_signer_info_methods[] = {
    PHP_ME(openssl_pkcs_signer_info, __construct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

void openssl_pkcs_init_signer_info(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\SignerInfo", openssl_pkcs_signer_info_methods);
    openssl_pkcs_signer_info_ce = zend_register_internal_class(&ce TSRMLS_CC);
    // flags
    openssl_pkcs_signer_info_ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
    // attributes
    zend_declare_property_null(openssl_pkcs_signer_info_ce, "issuer", strlen("issuer"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_signer_info_ce, "serialNumber", strlen("serialNumber"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_signer_info_ce, "digestAlgorithm", strlen("digestAlgorithm"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_signer_info_ce, "digestEncryptAlgorithm", strlen("digestEncryptAlgorithm"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(openssl_pkcs_signer_info_ce, "signingTime", strlen("signingTime"), ZEND_ACC_PRIVATE TSRMLS_CC);
}
