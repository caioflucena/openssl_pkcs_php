--TEST--
Check for openssl_pkcs exception with invalid file as constructor parameter
--SKIPIF--
<?php if (!extension_loaded("openssl_pkcs")) print "skip"; ?>
--FILE--
<?php 
$p7s = new Openssl\P7s('tests/001.phpt');
--EXPECTF--
Warning: invalid pkcs7 file. in %s on line %d
