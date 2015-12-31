#include "x509_php.h"

/**
 *
 */
PHP_METHOD(openssl_pkcs_x509, __construct) {
    int len;
    char * file;
    zval * param;
    BIO * bio = NULL;
    X509 * x509 = NULL;
    TSRMLS_FETCH();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|r", &file, &len, &param) == FAILURE) {
        return;
    }

    if (0 < len) {
        bio = BIO_new(BIO_s_file());
        BIO_read_filename(bio, file);
        if (NULL == bio) {
            free(bio);
            zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not read the x509 file.", 0 TSRMLS_CC);
            return;
        }

        x509 = PEM_read_bio_X509(bio,NULL,0,NULL);
    } else {
        ZEND_FETCH_RESOURCE(x509, X509*, &param, -1, PHP_OPENSSL_PKCS_X509_RESOURCE_NAME, le_openssl_x509_resource);
    }

    updatePropertyData(getThis(), x509);
    updatePropertyValidity(getThis(), x509);
    updatePropertyIssuerSubject(getThis(), x509, PHP_OPENSSL_PKCS_X509_ISSUER);
    updatePropertyIssuerSubject(getThis(), x509, PHP_OPENSSL_PKCS_X509_SUBJECT);
    updatePropertySubjectPublicKeyInfo(getThis(), x509);
    updatePropertyX509v3Extensions(getThis(), x509);

    free(x509);
    free(bio);
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
    zend_declare_property_null(openssl_pkcs_x509_ce, "data", sizeof("data")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "validity", sizeof("validity")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "issuer", sizeof("issuer")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "subject", sizeof("subject")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "subjectPublicKeyInfo", sizeof("subjectPublicKeyInfo")-1, ZEND_ACC_PRIVATE);
    zend_declare_property_null(openssl_pkcs_x509_ce, "x509v3Extensions", sizeof("x509v3Extensions")-1, ZEND_ACC_PRIVATE);
}

void updatePropertyData(void * object, X509 * x509) {
    zval * attribute;
    MAKE_STD_ZVAL(attribute);
    array_init(attribute);

    add_assoc_long(attribute, "version", ((int) X509_get_version(x509)) + 1);

    char * serialNumber = 0x0;
    ASN1_INTEGER *serial = X509_get_serialNumber(x509);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    serialNumber = BN_bn2dec(bn);
    BN_free(bn);
    add_assoc_string(attribute, "serialNumber", serialNumber, 1);
    free(serialNumber);

    zend_update_property(openssl_pkcs_x509_ce, object, "data", sizeof("data")-1, attribute TSRMLS_CC);
}

void updatePropertyValidity(void * object, X509 * x509) {
    zval * validityAttribute;
    zval * validityNotBefore;
    zval * validityNotAfter;

    MAKE_STD_ZVAL(validityAttribute);
    array_init(validityAttribute);

    MAKE_STD_ZVAL(validityNotBefore);
    getValidityDateTimeInstance(x509, validityNotBefore, PHP_OPENSSL_PKCS_X509_VALIDITY_BEFORE);
    add_assoc_zval(validityAttribute, "notBefore", validityNotBefore);

    MAKE_STD_ZVAL(validityNotAfter);
    getValidityDateTimeInstance(x509, validityNotAfter, PHP_OPENSSL_PKCS_X509_VALIDITY_AFTER);
    add_assoc_zval(validityAttribute, "notAfter", validityNotAfter);

    zend_update_property(openssl_pkcs_x509_ce, object, "validity", sizeof("validity")-1, validityAttribute);
}

void updatePropertyIssuerSubject(void * object, X509 * x509, char * type) {
    X509_NAME * x509Name;
    zval * attribute;
    MAKE_STD_ZVAL(attribute);
    array_init(attribute);

    if (type == PHP_OPENSSL_PKCS_X509_ISSUER) {
        x509Name = X509_get_issuer_name(x509);
    }

    if (type == PHP_OPENSSL_PKCS_X509_SUBJECT) {
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

    if (type == PHP_OPENSSL_PKCS_X509_ISSUER) {
        zend_update_property(openssl_pkcs_x509_ce, object, "issuer", sizeof("issuer")-1, attribute);
    }
    if (type == PHP_OPENSSL_PKCS_X509_SUBJECT) {
        zend_update_property(openssl_pkcs_x509_ce, object, "subject", sizeof("subject")-1, attribute);
    }
}

void updatePropertySubjectPublicKeyInfo(void * object, X509 * x509) {
    zval * attribute;
    MAKE_STD_ZVAL(attribute);
    array_init(attribute);

    EVP_PKEY * pubkey = X509_get_pubkey(x509);
    RSA * rsa = EVP_PKEY_get1_RSA(pubkey);

    // bites
    add_assoc_long(attribute, "publicKey", EVP_PKEY_bits(pubkey));

    // algorithm
    int pkey_nid = OBJ_obj2nid(x509->cert_info->key->algor->algorithm);
    char * publicKeyAlgorithm = (char *)OBJ_nid2ln(pkey_nid);
    add_assoc_string(attribute, "algorithm", publicKeyAlgorithm, 1);

    // exponent
    add_assoc_string(attribute, "exponent", BN_bn2dec(rsa->e), 1);

    // modulus
    add_assoc_string(attribute, "modulus", BN_bn2hex(rsa->n), 1);

    RSA_free(rsa);
    EVP_PKEY_free(pubkey);

    zend_update_property(openssl_pkcs_x509_ce, object, "subjectPublicKeyInfo", sizeof("subjectPublicKeyInfo")-1, attribute TSRMLS_CC);
}

void updatePropertyX509v3Extensions(void * object, X509 * x509) {
    zval * attribute;
    MAKE_STD_ZVAL(attribute);
    array_init(attribute);

    STACK_OF(X509_EXTENSION) *exts = x509->cert_info->extensions;
    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
    }

    int i;
    for (i=0; i < num_of_exts; i++) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        unsigned nid = OBJ_obj2nid(obj);

        char extname[500];
        OBJ_obj2txt(extname, 500, (const ASN1_OBJECT *) obj, 1);

        BUF_MEM *bptr = NULL;
        char *buf = NULL;
        int loc;
        loc = X509_get_ext_by_NID(x509, nid, -1);
        ex = X509_get_ext(x509, loc);

        BIO *bio = BIO_new(BIO_s_mem());
        if(!X509V3_EXT_print(bio, ex, 0, 0)){
            continue;
        }
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
            bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
            bptr->data[lastchar] = (char) 0;
        }

        buf = (char *)malloc( (bptr->length + 1)*sizeof(char) );
        memcpy(buf, bptr->data, bptr->length);

        const char *c_ext_name = OBJ_nid2ln(nid);
        char * name = malloc(strlen(c_ext_name)+1);
        memcpy(name, c_ext_name, strlen(c_ext_name)+1);
        add_assoc_string(attribute, name, buf, 1);

        free(buf);
        free(name);
        BIO_free(bio);
    }

    zend_update_property(openssl_pkcs_x509_ce, object, "x509v3Extensions", sizeof("x509v3Extensions")-1, attribute TSRMLS_CC);
}


/**
 *
 */
void getValidityDateTimeInstance(X509 * x509, zval * dateTime, char * type) {
    char * dateTimeChar;
    ASN1_TIME * asn1Time;
    zend_class_entry * dateTimeCE;
    zval * param;

    dateTimeCE = php_date_get_date_ce();
    dateTimeChar = (char *) malloc(sizeof(char) * 128);

    if (type == PHP_OPENSSL_PKCS_X509_VALIDITY_BEFORE) {
        asn1Time = X509_get_notBefore(x509);
    } else {
        asn1Time = X509_get_notAfter(x509);
    }
    int rc;

    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, asn1Time);
    if (rc <= 0) {
        BIO_free(b);
        return;
    }
    rc = BIO_gets(b, dateTimeChar, 128);
    if (rc <= 0) {
        BIO_free(b);
        return;
    }
    BIO_free(b);

    object_init_ex(dateTime, dateTimeCE);
    MAKE_STD_ZVAL(param);
    ZVAL_STRING(param, dateTimeChar, 1);
    if (zend_call_method(&dateTime, dateTimeCE, &dateTimeCE->constructor, ZEND_STRL(dateTimeCE->constructor->common.function_name), NULL, 1, param, NULL) == EXIT_FAILURE) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "Could not create validity not before datetime object.", 0 TSRMLS_CC);
        return;
    }
}
