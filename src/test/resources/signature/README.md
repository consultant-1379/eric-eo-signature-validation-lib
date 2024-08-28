## Testing
### Certificates and CMS generation

Certificates generation requires configuration file. Here is a sample minimal configuration file that could be adjusted further to model different scenarios:

```
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
commonName = Common Name

[root]
keyUsage = keyCertSign, cRLSign
basicConstraints = critical, CA:true

[intermediate]
keyUsage = keyCertSign
basicConstraints = critical, CA:true, pathlen:10

[signing]
keyUsage = digitalSignature
```

Following sequence of commands generates (and displays) a certificate chain, from self-signed root certificate to the leaf certificate:

```bash
# 1. Certificates to be placed in trust store

# generate self-signed root certificate
openssl req -x509 -days 36500 -nodes -newkey rsa:2048 -keyout root_ca.key -out root_ca.cert -config cert_config.cnf -extensions root
openssl x509 -in root_ca.cert -text -noout

# generate first intermediate CA certificate signed by root certificate
openssl req -new -nodes -keyout intermediate_1_ca.key -out intermediate_1_ca.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_1_ca.csr -CA root_ca.cert -CAkey root_ca.key -out intermediate_1_ca.cert -extfile cert_config.cnf -extensions intermediate -CAcreateserial
openssl x509 -in intermediate_1_ca.cert -text -noout

# generate second intermediate CA certificate signed by first intermediate CA certificate
openssl req -new -nodes -keyout intermediate_2_ca.key -out intermediate_2_ca.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_2_ca.csr -CA intermediate_1_ca.cert -CAkey intermediate_1_ca.key -out intermediate_2_ca.cert -extfile cert_config.cnf -extensions intermediate -CAcreateserial
openssl x509 -in intermediate_2_ca.cert -text -noout

# generate signing certificate signed by second intermediate CA certificate
openssl req -new -nodes -keyout signing_1_ca.key -out signing_1_ca.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in signing_1_ca.csr -CA intermediate_2_ca.cert -CAkey intermediate_2_ca.key -out signing_1_ca.cert -extfile cert_config.cnf -extensions signing -CAcreateserial
openssl x509 -in signing_1_ca.cert -text -noout

# 2. Certificates to be placed in external certificate container

# generate first intermediate external certificate signed by second intermediate CA certificate
openssl req -new -nodes -keyout intermediate_1_external.key -out intermediate_1_external.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_1_external.csr -CA intermediate_2_ca.cert -CAkey intermediate_2_ca.key -out intermediate_1_external.cert -extfile cert_config.cnf -extensions intermediate
openssl x509 -in intermediate_1_external.cert -text -noout

# generate second intermediate external certificate signed by first intermediate external certificate
openssl req -new -nodes -keyout intermediate_2_external.key -out intermediate_2_external.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_2_external.csr -CA intermediate_1_external.cert -CAkey intermediate_1_external.key -out intermediate_2_external.cert -extfile cert_config.cnf -extensions intermediate -CAcreateserial
openssl x509 -in intermediate_2_external.cert -text -noout

# generate signing certificate signed by second intermediate external certificate
openssl req -new -nodes -keyout signing_1_external.key -out signing_1_external.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in signing_1_external.csr -CA intermediate_2_external.cert -CAkey intermediate_2_external.key -out signing_1_external.cert -extfile cert_config.cnf -extensions signing -CAcreateserial
openssl x509 -in signing_1_external.cert -text -noout

# 3. Certificates to be packaged in CMS along with signature(s)

# generate first intermediate embedded certificate signed by second intermediate external certificate
openssl req -new -nodes -keyout intermediate_1_embedded.key -out intermediate_1_embedded.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_1_embedded.csr -CA intermediate_2_external.cert -CAkey intermediate_2_external.key -out intermediate_1_embedded.cert -extfile cert_config.cnf -extensions intermediate
openssl x509 -in intermediate_1_embedded.cert -text -noout

# generate second intermediate embedded certificate signed by forst intermediate embedded certificate
openssl req -new -nodes -keyout intermediate_2_embedded.key -out intermediate_2_embedded.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in intermediate_2_embedded.csr -CA intermediate_1_embedded.cert -CAkey intermediate_1_embedded.key -out intermediate_2_embedded.cert -extfile cert_config.cnf -extensions intermediate -CAcreateserial
openssl x509 -in intermediate_2_embedded.cert -text -noout

# generate signing certificate signed by second intermediate embedded certificate
openssl req -new -nodes -keyout signing_1_embedded.key -out signing_1_embedded.csr -config cert_config.cnf
openssl x509 -req -days 36500 -in signing_1_embedded.csr -CA intermediate_2_embedded.cert -CAkey intermediate_2_embedded.key -out signing_1_embedded.cert -extfile cert_config.cnf -extensions signing -CAcreateserial
openssl x509 -in signing_1_embedded.cert -text -noout
```

Now when we're all set with the certificates it's time to create signatures for some content. It is assumed further that the content is stored in a file named `data.txt`:

```bash
# prepare certificates that will be packaged in CMS along with signatures
cat intermediate_1_embedded.cert > embedded.pem
cat intermediate_2_embedded.cert >> embedded.pem

# create CMS with first signature (with embedded signing certificate) and all embedded certificates (signing + two intermediate)
openssl cms -sign -in data.txt -binary -inkey signing_1_embedded.key -signer signing_1_embedded.cert -out signature.cms -outform pem -certfile embedded.pem

# Add second signature (with external signing certificate), don't put certificate to CMS
openssl cms -resign -in signature.cms -inform pem -inkey signing_1_external.key -signer signing_1_external.cert -out signature.cms -outform pem -nocerts

# Add third signature (with CA signing certificate), don't put certificate to CMS
openssl cms -resign -in signature.cms -inform pem -inkey signing_1_ca.key -signer signing_1_ca.cert -out signature.cms -outform pem -nocerts

# show CMS content and verify there are 3 signatures and 3 embedded certificates
openssl cms -cmsout -in signature.cms -inform pem -print -noout
```

When CMS file is created, the last step is to prepare files for trust store and external certificate container:

```bash
# create file for trust store
cat root_ca.cert > ca.pem; cat intermediate_1_ca.cert >> ca.pem;cat intermediate_2_ca.cert >> ca.pem;cat signing_1_ca.cert >> ca.pem

# create external certificates container
cat intermediate_1_external.cert > external.pem;cat intermediate_2_external.cert >> external.pem;cat signing_1_external.cert >> external.pem
```

As a result there sould be following files for using in tests:
* ca.pem - certificates for trust store
* certificate.pem - external (with regard to signature) certificates
* signature.cms - digital signature and certiticates
* data.txt - content for which signature(s) were created
