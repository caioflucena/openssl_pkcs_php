#include "php_x509.h"

/**
 *
 */
PHP_METHOD(openssl_pkcs_x509, __construct) {
    int len;
    char * file;
    X509 * x509;
    long version;
    zval * versionAttribute;
    char * serialNumber;
    zval * serialNumberAttribute;
    //char * signatureAlgorithm[SIGNATURE_ALGORITHM_LENGTH];
    //zval * signatureAlgorithmAttribute;
    char * validityNotBefore;
    zval * validityNotBeforeDateParam;
    zval * validityNotBeforeAttribute;
    char * validityNotAfter;
    zval * validityNotAfterDateParam;
    zval * validityNotAfterAttribute;
    zend_class_entry * dateTimeCE;
    TSRMLS_FETCH();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &file, &len) == FAILURE) {
        return;
    }

    x509 = (X509 *) malloc(sizeof(X509));
    if (getX509FromFile(file, x509) == EXIT_FAILURE) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read the x509 file.", 0 TSRMLS_CC);
        php_error(E_ERROR, "Could not read the X509.");
    }

    if (getVersion(x509, &version) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 version.");
    }
    MAKE_STD_ZVAL(versionAttribute);
    ZVAL_LONG(versionAttribute, version);
    zend_update_property(openssl_pkcs_x509_ce, getThis(), "version", sizeof("version")-1, versionAttribute TSRMLS_CC);

    serialNumber = (char *) malloc(sizeof(char) * SERIAL_NUMBER_LENGTH);
    if (getSerialNumber(x509, serialNumber) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 serial number.");
    }
    MAKE_STD_ZVAL(serialNumberAttribute);
    ZVAL_STRING(serialNumberAttribute, serialNumber, 1);
    free(serialNumber);
    zend_update_property(openssl_pkcs_x509_ce, getThis(), "serialNumber", sizeof("serialNumber")-1, serialNumberAttribute TSRMLS_CC);

    //if (getSignatureAlgorithm(x509, signatureAlgorithm) == EXIT_FAILURE) {
    //    php_error(E_ERROR, "Could not read X509 signature algorithm.");
    //}
    //MAKE_STD_ZVAL(signatureAlgorithmAttribute);
    //ZVAL_STRING(signatureAlgorithmAttribute, signatureAlgorithm, 1);
    //zend_update_property(openssl_pkcs_x509_ce, getThis(), "signatureAlgorithm", sizeof("signatureAlgorithm")-1, signatureAlgorithmAttribute TSRMLS_CC);

    dateTimeCE = php_date_get_date_ce();

    validityNotBefore = (char *) malloc(sizeof(char) * DATE_LENGTH);
    if (getValidityNotBefore(x509, validityNotBefore) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 validity not before.");
    }
    MAKE_STD_ZVAL(validityNotBeforeAttribute);
    object_init_ex(validityNotBeforeAttribute, dateTimeCE);
    MAKE_STD_ZVAL(validityNotBeforeDateParam);
    ZVAL_STRING(validityNotBeforeDateParam, validityNotBefore, 1);
    free(validityNotBefore);
    if (zend_call_method(&validityNotBeforeAttribute, dateTimeCE, &dateTimeCE->constructor, ZEND_STRL(dateTimeCE->constructor->common.function_name), NULL, 1, validityNotBeforeDateParam TSRMLS_CC) == EXIT_FAILURE) {
        php_error(E_WARNING, "Could not create validity not before datetime object.");
    }
    zend_update_property(openssl_pkcs_x509_ce, getThis(), "validityNotBefore", sizeof("validityNotBefore")-1, validityNotBeforeAttribute);

    validityNotAfter = (char *) malloc(sizeof(char) * DATE_LENGTH);
    if (getValidityNotAfter(x509, validityNotAfter) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 validity not after.");
    }
    MAKE_STD_ZVAL(validityNotAfterAttribute);
    object_init_ex(validityNotAfterAttribute, dateTimeCE);
    MAKE_STD_ZVAL(validityNotAfterDateParam);
    ZVAL_STRING(validityNotAfterDateParam, validityNotAfter, 1);
    free(validityNotAfter);
    if (zend_call_method(&validityNotAfterAttribute, dateTimeCE, &dateTimeCE->constructor, ZEND_STRL(dateTimeCE->constructor->common.function_name), NULL, 1, validityNotAfterDateParam TSRMLS_CC) == EXIT_FAILURE) {
        php_error(E_WARNING, "Could not create validity not after datetime object.");
    }
    zend_update_property(openssl_pkcs_x509_ce, getThis(), "validityNotAfter", sizeof("validityNotAfter")-1, validityNotAfterAttribute);

    free(x509);
}

/**
 *
 */
zend_class_entry * php_openssl_pkcs_get_x509_ce(void) {
    return openssl_pkcs_x509_ce;
}

/**
 * 
 */
static zend_function_entry openssl_pkcs_x509_methods[] = {
    PHP_ME(openssl_pkcs_x509, __construct, NULL, ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
    {NULL, NULL, NULL}
};

/**
 *
 */
void openssl_pkcs_init_x509(TSRMLS_D) {
    zend_class_entry ce;

    INIT_CLASS_ENTRY(ce, "Openssl\\X509", openssl_pkcs_x509_methods);
    openssl_pkcs_x509_ce = zend_register_internal_class(&ce TSRMLS_CC);

    // flags
    openssl_pkcs_x509_ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
    // attributes
    zend_declare_property_null(openssl_pkcs_x509_ce, "version", sizeof("version")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "serialNumber", sizeof("serialNumber")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "validityNotBefore", sizeof("validityNotBefore")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "validityNotAfter", sizeof("validityNotAfter")-1, ZEND_ACC_PRIVATE);
}

