#!/bin/bash
set -e
rm -rf certs && mkdir -p certs && cd certs

# 1. Root CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=DCSM-RootCA"

# 2. Gateway Server Certificate (SAN: gateway-service, localhost)
openssl req -newkey rsa:2048 -nodes \
  -keyout gateway.key -out gateway.csr -subj "/CN=gateway-service"
cat << 'EXT' > gateway.ext
subjectAltName = DNS:gateway-service,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth,clientAuth
EXT
openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out gateway.crt -days 365 -extfile gateway.ext

# 3. Storage Server Certificate (SAN: storage-service, localhost)
openssl req -newkey rsa:2048 -nodes \
  -keyout storage.key -out storage.csr -subj "/CN=storage-service"
cat << 'EXT' > storage.ext
subjectAltName = DNS:storage-service,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EXT
openssl x509 -req -in storage.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out storage.crt -days 365 -extfile storage.ext

# 4. Client Certificate (Valid)
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr -subj "/CN=valid-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# 5. Untrusted Client Certificate (Self-signed untuk uji penolakan mTLS)
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout bad_client.key -out bad_client.crt -subj "/CN=untrusted-client"

rm -f *.csr *.ext
chmod 644 *.crt *.key *.srl
echo "Sertifikat mTLS dengan SAN Kubernetes berhasil dibuat."
