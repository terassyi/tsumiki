# Tsumiki Examples

This directory contains examples demonstrating how to use `tsumiki` with `rustls` for TLS communication.

To enable rustls integration, add the `rustls` feature to `x509` and `pkcs` crates:

```toml
[dependencies]
x509 = { version = "0.0.1", features = ["rustls"] }
pkcs = { version = "0.0.1", features = ["rustls"] }
```

## mTLS Echo Server/Client

A mutual TLS (mTLS) echo server and client that demonstrates:

- Loading X.509 certificates and private keys from PEM files using `tsumiki`
- Converting `tsumiki` types to `rustls` types for TLS operations
- Custom certificate verification using `tsumiki` to inspect certificates during handshake

### Running the Example

Start the server:

```bash
cargo run --bin tls-echo-server
```

In another terminal, run the client:

```bash
cargo run --bin tls-echo-client
```

You can also test with OpenSSL:

```bash
echo "hello" | openssl s_client -connect localhost:8443 \
    -cert examples/certs/client.crt \
    -key examples/certs/client.key \
    -CAfile examples/certs/ca.crt \
    -quiet
```

## Code Highlights

### Loading Certificates from PEM

`tsumiki` can parse PEM files and decode them into structured types:

```rust
use tsumiki::decoder::Decoder;
use x509::Certificate;

let pem = fs::read_to_string("server.crt")?.parse::<pem::Pem>()?;
let cert: Certificate = pem.decode()?;

// Access certificate fields
println!("Subject: {}", cert.tbs_certificate().subject());
println!("Issuer: {}", cert.tbs_certificate().issuer());
println!("Not After: {}", cert.tbs_certificate().validity().not_after());
```

### Loading Private Keys from PEM

The `PrivateKey` enum automatically detects the key format (PKCS#1 RSA, SEC1 EC, or PKCS#8):

```rust
use pkcs::PrivateKey;

let pem = fs::read_to_string("server.key")?.parse::<pem::Pem>()?;
let key: PrivateKey = pem.decode()?;

println!("Algorithm: {}", key.algorithm());
println!("Key size: {} bits", key.key_size());
```

### Converting to Rustls Types

With the `rustls` feature enabled, tsumiki types can be converted to rustls types via `TryFrom`:

```rust
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// Certificate: tsumiki -> rustls
let rustls_cert = CertificateDer::try_from(&cert)?;

// Private key: tsumiki -> rustls
let rustls_key = PrivateKeyDer::try_from(key)?;

// Certificate: rustls -> tsumiki (for inspection during TLS handshake)
let tsumiki_cert = Certificate::try_from(rustls_cert)?;
```

## Generating Test Certificates

The `certs/` directory contains pre-generated X.509 v3 certificates. To regenerate them:

```bash
cd examples/certs

cat > openssl.cnf << 'EOF'
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[v3_client]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 365 \
    -subj "/C=JP/O=Tsumiki/CN=Tsumiki Example CA" -extensions v3_ca -config openssl.cnf

# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=JP/O=Tsumiki Server/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile openssl.cnf -extensions v3_server

# Client
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/C=JP/O=Tsumiki Client/CN=client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -extfile openssl.cnf -extensions v3_client

rm -f *.csr openssl.cnf
```

**Note:** rustls requires X.509 v3 certificates with proper extensions.
