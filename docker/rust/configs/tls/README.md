# TLS Certificates for SEPP

This directory should contain TLS certificates for SEPP (Security Edge Protection Proxy) N32 interface.

## Required Files

For SEPP1 (Home PLMN):
- `sepp1.key` - Private key for SEPP1
- `sepp1.crt` - Certificate for SEPP1

For SEPP2 (Visited PLMN):
- `sepp2.key` - Private key for SEPP2
- `sepp2.crt` - Certificate for SEPP2

Common:
- `ca.crt` - CA certificate for verification

## Generating Test Certificates

You can generate test certificates using the following commands:

```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=NextGCore CA"

# Generate SEPP1 key and certificate
openssl genrsa -out sepp1.key 2048
openssl req -new -key sepp1.key -out sepp1.csr \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=sepp1.localdomain"
openssl x509 -req -days 365 -in sepp1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out sepp1.crt

# Generate SEPP2 key and certificate
openssl genrsa -out sepp2.key 2048
openssl req -new -key sepp2.key -out sepp2.csr \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=sepp2.localdomain"
openssl x509 -req -days 365 -in sepp2.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out sepp2.crt

# Clean up CSR files
rm -f sepp1.csr sepp2.csr
```

## Production Use

For production deployments, use properly signed certificates from a trusted CA.
