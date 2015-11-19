## openssl-pkcs7

#### First you must get the PHP source code and checkout to the desired revision or tag
  - git clone https://github.com/php/php-src.git
  - cd php-src
  - git checkout {DESIRED_TAG} (e.g. git checkout php-5.6.15)

#### Next clone the Openssl_Pkcs source code inside the PHP extension folder
  - cd ext
  - git clone https://github.com/caioflucena/openssl_pkcs.git
  - cd openssl_pkcs
  - git checkout {DESIRED_TAG} (e.g. git checkout 0.1.0)

#### Now compile the extension and move (or create a symbolic link) to the PHP default extention folder of your operational system
  - phpize && ./configure && make
  - if you don't know where it is on your OS you can run the following command
    - php-config --extension-dir
  - mv openssl_pkcs.so {EXTENSION_FOLDER} (e.g. /usr/lib64/php/modules/)
  - If you are using apache enable the extension
    - echo 'extension=openssl_pkcs.so' >> {YOUR_PHP_INI_FILE} (e.g. /etc/php.ini)
    - service httpd restart

Feel free to contribute and see how to use the extension on PHP here (por o link do projeto de demonstração aqui)
