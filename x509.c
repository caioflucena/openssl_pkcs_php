#include "x509.h"

int getX509FromFile(char * file, X509 * x509) {
    BIO * bio = NULL;
          bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, file);
    if (NULL == bio) {
        BIO_free(bio);
        return EXIT_FAILURE;
    }

    X509 * out = PEM_read_bio_X509(bio,NULL,0,NULL);
    if (NULL == out) {
        X509_free(out);
        BIO_free(bio);
        return EXIT_FAILURE;
    }
    memcpy(x509, out, sizeof(X509));
    if (NULL == x509) {
        X509_free(out);
        BIO_free(bio);
        return EXIT_FAILURE;
    }

    //X509_free(out);
    BIO_free(bio);
    return EXIT_SUCCESS;
}

int getVersion(X509 * x509, long * version) {
    if (NULL == x509) {
        return EXIT_FAILURE;
    }
    *version = ((int) X509_get_version(x509)) + 1;
    return EXIT_SUCCESS;
}

int getSerialNumber(X509 * x509, char * serialNumber) {
    ASN1_INTEGER *serial = X509_get_serialNumber(x509);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) {
        return EXIT_FAILURE;
    }
    char *tmp = BN_bn2dec(bn);
    if (!tmp) {
        BN_free(bn);
        return EXIT_FAILURE;
    }
    if (strlen(tmp) >= SERIAL_NUMBER_LENGTH) {
        BN_free(bn);
        OPENSSL_free(tmp);
        return EXIT_FAILURE;
    }
    strncpy(serialNumber, tmp, SERIAL_NUMBER_LENGTH);
    BN_free(bn);
    OPENSSL_free(tmp);
    return EXIT_SUCCESS;
}

int getSignatureAlgorithm(X509 * x509, char * signatureAlgorithm) {
    memcpy(signatureAlgorithm, "asd", 3);
    
    int pkey_nid = OBJ_obj2nid(x509->cert_info->key->algor->algorithm);
    if (pkey_nid == NID_undef) {
        return EXIT_FAILURE;
    }
    
    const char* sslbuf = OBJ_nid2ln(pkey_nid);
    if (NULL == sslbuf) {// strlen(sslbuf) > 3) {
        return EXIT_FAILURE;
    }
    strncpy(signatureAlgorithm, sslbuf, strlen(sslbuf));
    
    return EXIT_SUCCESS;
}

int getValidityNotBefore(X509 * x509, char * validityNotBefore) {
    ASN1_TIME *not_before = X509_get_notBefore(x509);
    int rc;

    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, not_before);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, validityNotBefore, DATE_LENGTH);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);

    return EXIT_SUCCESS;
}

int getValidityNotAfter(X509 * x509, char * validityNotAfter) {
    ASN1_TIME *not_after = X509_get_notAfter(x509);
    int rc;

    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, not_after);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, validityNotAfter, DATE_LENGTH);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);

    return EXIT_SUCCESS;
}

int getIssuer(X509 * x509, char * issuer) {
    char * tmp = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);
    memcpy(issuer, tmp, strlen(tmp));
    return EXIT_SUCCESS;
}

int getSubject(X509 * x509, char * subject) {
    char * tmp = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    memcpy(subject, tmp, strlen(tmp));
    return EXIT_SUCCESS;
}
