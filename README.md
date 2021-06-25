## Openssl pkcs7

The purpose of this extension is cover the signature and content extraction on p7s files, besides verify if given file was signed.

#### First you must get the PHP source code and checkout to the desired revision or tag
    git clone https://github.com/php/php-src.git
    cd php-src
    git checkout {DESIRED_TAG} (e.g. git checkout php-5.6.15)

#### Next clone the Openssl_Pkcs source code inside the PHP extension folder
    cd ext
    git clone https://github.com/caioflucena/openssl_pkcs_php.git
    cd openssl_pkcs
    git checkout {DESIRED_TAG} (e.g. git checkout 0.2.1)

#### Now compile and install the extension

    phpize && ./configure && make
    php-config --extension-dir | awk '{print "mv modules/openssl_pkcs.so " $1}' | sh
    php -i | grep "Loaded Configuration File" | awk '{print "echo \"extension=openssl_pkcs.so\" >> " $5}' | sh
    service httpd restart

#### Have fun

Create a self-signed certificate.
```
openssl req -x509 -sha256 -nodes -days 365 \
 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```
Create a message file.
```
echo "I am a message" > message.txt
```
Sign the message file.
```
openssl smime -sign -binary -nodetach \
 -in message.txt -out message.txt.signed -outform der -inkey privateKey.key -signer certificate.crt
```
PHP :)
```php
$p7s = new Openssl\P7s('message.txt.signed');

# get signature(s)
$p7s->getSignature();
// returns an array that contains the signers list
// Array (
//  [0] => Array (
//    [datetime] => DateTime Object (
//      [date] => 2015-11-20 17:41:26.000000
//      [timezone_type] => 3
//      [timezone] => America/Sao_Paulo
//    )
//    [signer] => Array (
//      [commonName] => Organization Name X Common Name
//      [serialNumber] => -1658951932288993633
//    )
//  )
// )

# get content
$p7s->getContent(); // returns the content on hexadecimal format (4920616d2061206d6573736167650a)
// to print the original message
echo hex2bin($p7s->getContent());

# verify
$p7s->verify('message.txt'); // returns a boolean
```
