#include "x509.h"

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
