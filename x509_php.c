#include "x509_php.h"

/**
 *
 */
PHP_METHOD(openssl_pkcs_x509, __construct) {
    int len;
    char * file;
    zval * param;
    X509 * x509;
    TSRMLS_FETCH();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|r", &file, &len, &param) == FAILURE) {
        return;
    }

    if (0 < len) {
        x509 = (X509 *) malloc(sizeof(X509));
        if (getX509FromFile(file, x509) == EXIT_FAILURE) {
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read the x509 file.", 0 TSRMLS_CC);
        }
    } else {
        ZEND_FETCH_RESOURCE(x509, X509*, &param, -1, PHP_OPENSSL_PKCS_X509_RESOURCE_NAME, le_openssl_x509_resource);
    }

    updatePropertyPublicKeyAlgorithm(getThis(), x509);
    updatePropertyVersion(getThis(), x509);
    updatePropertySerialNumber(getThis(), x509);
    updatePropertyValidity(getThis(), x509);
    updatePropertyIssuerSubject(getThis(), x509, PHP_OPENSSL_PKCS_X509_ISSUER);
    updatePropertyIssuerSubject(getThis(), x509, PHP_OPENSSL_PKCS_X509_SUBJECT);

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
    zend_declare_property_null(openssl_pkcs_x509_ce, "publicKeyAlgorithm", sizeof("publicKeyAlgorithm")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "validity", sizeof("validity")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "issuer", sizeof("issuer")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "subject", sizeof("subject")-1, ZEND_ACC_PRIVATE);
}

void updatePropertyPublicKeyAlgorithm(void * object, X509 * x509) {
    char * publicKeyAlgorithm;
    zval * publicKeyAlgorithmAttribute;
    publicKeyAlgorithm = malloc(SIGNATURE_ALGORITHM_LENGTH * sizeof(char));
    if (getSignatureAlgorithm(x509, publicKeyAlgorithm) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 public key algorithm.");
    }
    MAKE_STD_ZVAL(publicKeyAlgorithmAttribute);
    ZVAL_STRING(publicKeyAlgorithmAttribute, publicKeyAlgorithm, 1);
    zend_update_property(openssl_pkcs_x509_ce, object, "publicKeyAlgorithm", sizeof("publicKeyAlgorithm")-1, publicKeyAlgorithmAttribute TSRMLS_CC);
}

void updatePropertyVersion(void * object, X509 * x509) {
    long version;
    zval * versionAttribute;
    if (getVersion(x509, &version) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 version.");
    }
    MAKE_STD_ZVAL(versionAttribute);
    ZVAL_LONG(versionAttribute, version);
    zend_update_property(openssl_pkcs_x509_ce, object, "version", sizeof("version")-1, versionAttribute TSRMLS_CC);
}

void updatePropertySerialNumber(void * object, X509 * x509) {
    char * serialNumber;
    zval * serialNumberAttribute;
    serialNumber = (char *) malloc(sizeof(char) * SERIAL_NUMBER_LENGTH);
    if (getSerialNumber(x509, serialNumber) == EXIT_FAILURE) {
        php_error(E_ERROR, "Could not read X509 serial number.");
    }
    MAKE_STD_ZVAL(serialNumberAttribute);
    ZVAL_STRING(serialNumberAttribute, serialNumber, 1);
    free(serialNumber);
    zend_update_property(openssl_pkcs_x509_ce, object, "serialNumber", sizeof("serialNumber")-1, serialNumberAttribute TSRMLS_CC);
}

void updatePropertyValidity(void * object, X509 * x509) {
    zend_class_entry * dateTimeCE;
    zval * validityAttribute;
    char * validityNotBefore;
    zval * validityNotBeforeDateParam;
    zval * validityNotBeforeAttribute;
    char * validityNotAfter;
    zval * validityNotAfterDateParam;
    zval * validityNotAfterAttribute;

    dateTimeCE = php_date_get_date_ce();

    MAKE_STD_ZVAL(validityAttribute);
    array_init(validityAttribute);

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
    add_assoc_zval(validityAttribute, "notBefore", validityNotBeforeAttribute);

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
    add_assoc_zval(validityAttribute, "notAfter", validityNotAfterAttribute);

    zend_update_property(openssl_pkcs_x509_ce, object, "validity", sizeof("validity")-1, validityAttribute);
}

void updatePropertyIssuerSubject(void * object, X509 * x509, char * type) {
    X509_NAME * x509Name;
    zval * attribute;
    MAKE_STD_ZVAL(attribute);
    array_init(attribute);

    char * content;

    if (type == PHP_OPENSSL_PKCS_X509_ISSUER) {
        content = malloc(ISSUER_LENGTH);
        memset(content, 0, ISSUER_LENGTH);
        if (getIssuer(x509, content) == EXIT_FAILURE) {
            php_error(E_ERROR, "Could not read X509 issuer.");
        }
        x509Name = X509_get_issuer_name(x509);
    }

    if (type == PHP_OPENSSL_PKCS_X509_SUBJECT) {
        content = malloc(SUBJECT_LENGTH);
        memset(content, 0, SUBJECT_LENGTH);
        if (getSubject(x509, content) == EXIT_FAILURE) {
            php_error(E_ERROR, "Could not read X509 subject.");
        }
        x509Name = X509_get_subject_name(x509);
    }


    // country name
    char * countryNameAttribute = NULL;
    int countryNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_countryName, -1);
    if (-1 < countryNameIndex) {
        X509_NAME_ENTRY *countryNameEntry = X509_NAME_get_entry(x509Name, countryNameIndex);
        ASN1_STRING *countryNameEntryData = X509_NAME_ENTRY_get_data(countryNameEntry);
        countryNameAttribute = ASN1_STRING_data(countryNameEntryData);
    } else {
        countryNameAttribute = malloc(sizeof(char));
        *countryNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "countryName", countryNameAttribute, 1);

    // state name
    char * stateNameAttribute = NULL;
    int stateNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_stateOrProvinceName, -1);
    if (-1 < stateNameIndex) {
        X509_NAME_ENTRY *stateNameEntry = X509_NAME_get_entry(x509Name, stateNameIndex);
        ASN1_STRING *stateNameEntryData = X509_NAME_ENTRY_get_data(stateNameEntry);
        stateNameAttribute = ASN1_STRING_data(stateNameEntryData);
    } else {
        stateNameAttribute = malloc(sizeof(char));
        *stateNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "stateOrProvinceName", stateNameAttribute, 1);

    // locality name
    char * localityNameAttribute = NULL;
    int localityNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_localityName, -1);
    if (-1 < localityNameIndex) {
        X509_NAME_ENTRY *localityNameEntry = X509_NAME_get_entry(x509Name, localityNameIndex);
        ASN1_STRING *localityNameEntryData = X509_NAME_ENTRY_get_data(localityNameEntry);
        localityNameAttribute = ASN1_STRING_data(localityNameEntryData);
    } else {
        localityNameAttribute = malloc(sizeof(char));
        *localityNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "localityName", localityNameAttribute, 1);

    // organization name
    char * organizationNameAttribute = NULL;
    int organizationNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_organizationName, -1);
    if (-1 < organizationNameIndex) {
        X509_NAME_ENTRY *organizationNameEntry = X509_NAME_get_entry(x509Name, organizationNameIndex);
        ASN1_STRING *organizationNameEntryData = X509_NAME_ENTRY_get_data(organizationNameEntry);
        organizationNameAttribute = ASN1_STRING_data(organizationNameEntryData);
    } else {
        organizationNameAttribute = malloc(sizeof(char));
        *organizationNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "organizationName", organizationNameAttribute, 1);

    // organization unit name
    char * organizationUnitNameAttribute = NULL;
    int organizationUnitNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_organizationalUnitName, -1);
    if (-1 < organizationUnitNameIndex) {
        X509_NAME_ENTRY *organizationUnitNameEntry = X509_NAME_get_entry(x509Name, organizationUnitNameIndex);
        ASN1_STRING *organizationUnitNameEntryData = X509_NAME_ENTRY_get_data(organizationUnitNameEntry);
        organizationUnitNameAttribute = ASN1_STRING_data(organizationUnitNameEntryData);
    } else {
        organizationUnitNameAttribute = malloc(sizeof(char));
        *organizationUnitNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "organizationUnitName", organizationUnitNameAttribute, 1);

    // common name
    char * commonNameAttribute = NULL;
    int commonNameIndex = X509_NAME_get_index_by_NID(x509Name, NID_commonName, -1);
    if (-1 < commonNameIndex) {
        X509_NAME_ENTRY *commonNameEntry = X509_NAME_get_entry(x509Name, commonNameIndex);
        ASN1_STRING *commonNameEntryData = X509_NAME_ENTRY_get_data(commonNameEntry);
        commonNameAttribute = ASN1_STRING_data(commonNameEntryData);
    } else {
        commonNameAttribute = malloc(sizeof(char));
        *commonNameAttribute = 0x0;
    }
    add_assoc_string(attribute, "commonName", commonNameAttribute, 1);

    // email address
    char * emailAddressAttribute = NULL;
    int emailAddressIndex = X509_NAME_get_index_by_NID(x509Name, NID_pkcs9_emailAddress, -1);
    if (-1 < emailAddressIndex) {
        X509_NAME_ENTRY *emailAddressEntry = X509_NAME_get_entry(x509Name, emailAddressIndex);
        ASN1_STRING *emailAddressEntryData = X509_NAME_ENTRY_get_data(emailAddressEntry);
        emailAddressAttribute = ASN1_STRING_data(emailAddressEntryData);
    } else {
        emailAddressAttribute = malloc(sizeof(char));
        *emailAddressAttribute = 0x0;
    }
    add_assoc_string(attribute, "emailAddress", emailAddressAttribute, 1);

    free(content);

    if (type == PHP_OPENSSL_PKCS_X509_ISSUER) {
        zend_update_property(openssl_pkcs_x509_ce, object, "issuer", sizeof("issuer")-1, attribute);
    }
    if (type == PHP_OPENSSL_PKCS_X509_SUBJECT) {
        zend_update_property(openssl_pkcs_x509_ce, object, "subject", sizeof("subject")-1, attribute);
    }
}
