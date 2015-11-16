<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('openssl_pkcs')) {
	dl('openssl_pkcs.' . PHP_SHLIB_SUFFIX);
}
$module = 'openssl_pkcs';
$functions = get_extension_funcs($module);
echo "Functions available in the test extension:$br\n";
foreach($functions as $func) {
    echo $func."$br\n";
}
echo "$br\n";
