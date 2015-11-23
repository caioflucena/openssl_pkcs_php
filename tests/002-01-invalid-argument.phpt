--TEST--
Check for openssl_pkcs exception with invalid file as constructor parameter
--SKIPIF--
<?php if (!extension_loaded("openssl_pkcs")) print "skip"; ?>
--FILE--
<?php 
$p7s = new Openssl\P7s();
--EXPECTF--
Warning: Openssl\P7s::__construct() expects exactly 1 parameter, 0 given in %s on line %d
