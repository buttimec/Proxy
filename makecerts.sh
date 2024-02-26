#!/usr/bin/env bash

# Adapted from 'Fixing Chrome 58+ [missing_subjectAltName] with openssl when using self signed certificates'
#   https://alexanderzeitler.com/articles/Fixing-Chrome-missing_subjectAltName-selfsigned-cert-openssl/
# with additional information from 'Certificates for localhost'
#   https://letsencrypt.org/docs/certificates-for-localhost

echo -e "\nGenerating root CA private key"
# generate 4096 bit private key using the RSA algorithm, encrypted with AES and pass phrase 'changeme'
# https://www.openssl.org/docs/man3.0/man1/openssl-genrsa.html
openssl genrsa -aes256 -passout pass:changeme -out ca.pass.key 4096

echo -e "\nConverting root CA private key to PEM format"
# https://www.openssl.org/docs/man3.0/man1/openssl-rsa.html
openssl rsa -passin pass:changeme -in ca.pass.key -out ca.key

echo -e "\nGenerating root CA certificate"
# generates v1 cert
#openssl req -new -x509 -days 365 -key ca.key -out ca.crt -config <( cat localhost.cnf )
# generates v3 cert
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj /C=IE/ST=Dublin/L=Somewhere/O=Someone/CN=localhost

# root CA certificate needs to be added to trusted cert store

#echo -e "\nGenerating server private key"
#openssl genrsa -aes256 -passout pass:changeme -out server.pass.key 4096

#echo -e "\nConverting server private key to PEM format"
#openssl rsa -passin pass:changeme -in server.pass.key -out server.key

#echo -e "\nGenerating certificate signing request"
#openssl req -new -key server.key -out server.csr -subj /C=IE/ST=Dublin/L=Somewhere/O=Someone/CN=localhost.com

#echo -e "\nGenerating certificate"
# https://www.openssl.org/docs/man3.0/man1/openssl-x509.html
# -reg : input certificate request
# -in : file to read certificate request from
# -CA : CA certificate to be used for signing
# -CAkey : CA private key to sign certificate (must match certificate in -CA)
# -days : number of days until a newly generated certificate expires
# -sha256 : sign with SHA256 message digest
# -extfile : Configuration file containing certificate and request X.509 extensions to add
#openssl x509 -CAcreateserial -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -out server.crt -extfile v3.ext

# verify certificate chains
# https://www.openssl.org/docs/man3.0/man1/openssl-verify.html
#openssl verify -show_chain -CAfile ca.crt server.crt

# https://knowledge.digicert.com/solution/verify-the-integrity-of-an-ssl-tls-certificate-and-private-key-pair

# confirm the Private Key's Integrity
# https://www.openssl.org/docs/man3.2/man1/openssl-rsa.html
# -check : checks the consistency of an RSA private key.
#openssl rsa -check -noout -in server.key

# view the certificate's Modulus
# https://www.openssl.org/docs/man3.2/man1/openssl-rsa.html
# -modulus : print out the value of the modulus of the key
#openssl rsa -modulus -noout -in server.key

# view the private key Modulus
# https://www.openssl.org/docs/man3.2/man1/openssl-x509.html
# -modulus : print out the value of the modulus of the public key contained in the certificate.
#openssl x509 -noout -modulus -in server.crt


#openssl x509 -in server.crt -text -noout

#openssl req -text -noout -verify -in server.csr