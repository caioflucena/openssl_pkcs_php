/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stdlib.h"
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_p7s.h"
#include "php_x509.h"

static int le_openssl_pkcs;

PHP_MINIT_FUNCTION(openssl_pkcs) {
    openssl_pkcs_init_p7s(TSRMLS_C);
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
    PHP_FE_END	/* Must be the last line in openssl_pkcs_functions[] */
};

zend_module_entry openssl_pkcs_module_entry = {
    STANDARD_MODULE_HEADER,
    "openssl_pkcs",
    openssl_pkcs_functions,
    PHP_MINIT(openssl_pkcs),
    PHP_MSHUTDOWN(openssl_pkcs),
    PHP_RINIT(openssl_pkcs),		/* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(openssl_pkcs),	/* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(openssl_pkcs),
    PHP_OPENSSL_PKCS_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OPENSSL_PKCS
ZEND_GET_MODULE(openssl_pkcs)
#endif
