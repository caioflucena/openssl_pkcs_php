--TEST--
Check for openssl_pkcs exception with invalid file as constructor parameter
--SKIPIF--
<?php if (!extension_loaded("openssl_pkcs")) print "skip"; ?>
--FILE--
<?php 
$p7s = new Openssl\P7s('error');
--EXPECTF--
Fatal error: Invalid File. in %s
