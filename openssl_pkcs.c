#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "openssl_pkcs.h"

PHP_MINIT_FUNCTION(openssl_pkcs) {
    openssl_pkcs_init_p7s(TSRMLS_C);
    openssl_pkcs_init_signed(TSRMLS_C);
    openssl_pkcs_init_signer_info(TSRMLS_C);
    openssl_pkcs_init_x509(TSRMLS_C);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(openssl_pkcs) {
    return SUCCESS;
}

PHP_RINIT_FUNCTION(openssl_pkcs) {
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(openssl_pkcs) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(openssl_pkcs) {
    php_info_print_table_start();
    php_info_print_table_header(2, "openssl_pkcs support", "enabled");
    php_info_print_table_end();
}

const zend_function_entry openssl_pkcs_functions[] = {
    PHP_FE_END
};

zend_module_entry openssl_pkcs_module_entry = {
    STANDARD_MODULE_HEADER,
    "openssl_pkcs",
    openssl_pkcs_functions,
    PHP_MINIT(openssl_pkcs),
    PHP_MSHUTDOWN(openssl_pkcs),
    PHP_RINIT(openssl_pkcs),
    PHP_RSHUTDOWN(openssl_pkcs),
    PHP_MINFO(openssl_pkcs),
    PHP_OPENSSL_PKCS_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OPENSSL_PKCS
ZEND_GET_MODULE(openssl_pkcs)
#endif
