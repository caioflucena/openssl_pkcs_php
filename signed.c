#include "signed.h"

PHP_METHOD(openssl_pkcs_signed, __construct) {
    zval * signedParam;
    PKCS7_SIGNED * p7sSigned;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|r", &signedParam) == FAILURE) {
        return;
    }

    ZEND_FETCH_RESOURCE(p7sSigned, PKCS7_SIGNED*, &signedParam, -1, PHP_OPENSSL_PKCS_SIGNED_RESOURCE_NAME, le_openssl_signed_resource);

    if (NULL == p7sSigned) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read signed resource.", 0 TSRMLS_CC);
        return;
    }

    zval * versionAttribute;
    MAKE_STD_ZVAL(versionAttribute);
    ZVAL_LONG(versionAttribute, ASN1_INTEGER_get(p7sSigned->version));
    zend_update_property(openssl_pkcs_signed_ce, getThis(), "version", strlen("version"), versionAttribute);

    zval * signerInfoAttribute;
    MAKE_STD_ZVAL(signerInfoAttribute);
    array_init(signerInfoAttribute);

    zend_class_entry * signerInfoCe = php_openssl_pkcs_get_signer_info_ce();
    PKCS7_SIGNER_INFO * p7sSignerInfo;
    STACK_OF(PKCS7_SIGNER_INFO) * p7sSignersInfo = p7sSigned->signer_info;
    int numSignerInfo = sk_PKCS7_SIGNER_INFO_num(p7sSignersInfo);
    int index;
    for (index = 0; index < numSignerInfo; ++index) {
        p7sSignerInfo = sk_PKCS7_SIGNER_INFO_value(p7sSignersInfo, index);

        zval * signerInfoInstance;
        MAKE_STD_ZVAL(signerInfoInstance);
        object_init_ex(signerInfoInstance, signerInfoCe);

        zval * signerInfoParam;
        MAKE_STD_ZVAL(signerInfoParam);
        int resourceID;
            resourceID = ZEND_REGISTER_RESOURCE(signerInfoParam, p7sSignerInfo, le_openssl_signer_info_resource);
        if (zend_call_method(&signerInfoInstance, signerInfoCe, &(signerInfoCe)->constructor, ZEND_STRL(signerInfoCe->constructor->common.function_name), NULL, 1, signerInfoParam, NULL) == EXIT_FAILURE) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create a signer info instance.", 0 TSRMLS_CC);
            return;
        }
        add_next_index_zval(signerInfoAttribute, signerInfoInstance);
    }
    zend_update_property(openssl_pkcs_signed_ce, getThis(), "signerInfo", strlen("signerInfo"), signerInfoAttribute);
}

/**
 *
 */
zend_class_entry * php_openssl_pkcs_get_signed_ce(void) {
    return openssl_pkcs_signed_ce;
}

/**
 *
 */
static zend_function_entry openssl_pkcs_signed_methods[] = {
    PHP_ME(openssl_pkcs_signed, __construct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

void openssl_pkcs_init_signed(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\Signed", openssl_pkcs_signed_methods);
    openssl_pkcs_signed_ce = zend_register_internal_class(&ce TSRMLS_CC);
    // flags
    openssl_pkcs_signed_ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
    // attributes
    zend_declare_property_null(openssl_pkcs_signed_ce, "version", strlen("version"), ZEND_ACC_PRIVATE TSRMLS_CC);
}
