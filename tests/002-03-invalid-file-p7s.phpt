--TEST--
Check for openssl_pkcs exception with invalid file as constructor parameter
--SKIPIF--
<?php if (!extension_loaded("openssl_pkcs")) print "skip"; ?>
--FILE--
<?php
try { 
    $p7s = new Openssl\P7s('tests/001.phpt');
} catch (Exception $e) {
    echo 'exception throwed';
}
--EXPECTF--
exception throwed
