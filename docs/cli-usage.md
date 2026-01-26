# tsumiki CLI Usage

tsumiki provides a command-line tool for inspecting X.509 certificates, ASN.1 structures, and PKCS keys.

## Installation

### From crates.io

```bash
cargo install tsumiki-cli
```

### From Source

```bash
git clone https://github.com/terassyi/tsumiki.git
cd tsumiki
cargo install --path cli
```

### From Release

Download pre-built binaries from [GitHub Releases](https://github.com/terassyi/tsumiki/releases):

- **Linux (x86_64, musl)**: `tsumiki-linux-amd64-vX.Y.Z.tar.gz`
- **Linux (arm64, musl)**: `tsumiki-linux-arm64-vX.Y.Z.tar.gz`
- **macOS (arm64)**: `tsumiki-darwin-arm64-vX.Y.Z.tar.gz`

Extract and install:

```bash
tar -xzf tsumiki-*.tar.gz
sudo mv tsumiki /usr/local/bin/
```

Verify installation:

```bash
tsumiki --help
```

## Commands Overview

```
tsumiki
├── cert inspect    # Inspect X.509 certificates
├── der inspect     # Convert PEM to DER (binary output)
├── der dump        # Display hex dump of DER file
├── der encode      # Convert DER to PEM
├── asn1 inspect    # Display ASN.1 structure
└── pkcs inspect    # Inspect PKCS keys
```

## Certificate Inspection

The `cert inspect` command displays X.509 certificate information.

### Help Output

```console
$ tsumiki cert inspect -h
Inspect and display a certificate

Usage: tsumiki cert inspect [OPTIONS] [FILE]

Arguments:
  [FILE]  Path to the certificate file (PEM or DER format). If not specified, reads from stdin

Options:
      --remote <REMOTE>
          Fetch certificate from remote TLS server (e.g., "example.com" or "example.com:443")
  -o, --output <OUTPUT>
          Output format [default: text] [possible values: text, json, yaml, brief]
      --show-subject
          Show only subject
      --show-issuer
          Show only issuer
      --show-dates
          Show only validity dates
      --show-serial
          Show only serial number
      --list-extensions
          List all extensions
      --show-algorithms
          Show algorithm information
      --show-oid
          Show OID values instead of human-readable names
      --show-fingerprint
          Show SHA256 fingerprint
      --check-expiry
          Check certificate expiry
      --fingerprint-alg <FINGERPRINT_ALG>
          Fingerprint algorithm (SHA1, SHA256, SHA512) [default: sha256]
      --show-pubkey
          Show public key in PEM format
      --show-purposes
          Show certificate purposes (from Extended Key Usage extension)
      --show-san
          Show Subject Alternative Names (SAN)
      --check-self-signed
          Check if certificate is self-signed
  -1, --first
          Show only the first certificate in the chain
      --index <INDEX>
          Show only the certificate at the specified index (0-indexed)
      --depth <DEPTH>
          Show only the first N certificates in the chain
      --root
          Show only the root certificate (self-signed) if present
      --no-header
          Hide certificate index headers (--- Certificate N ---)
  -h, --help
          Print help
```

### Basic Usage

```bash
# Inspect a local certificate file (PEM or DER)
tsumiki cert inspect certificate.pem

# Read from stdin
cat certificate.pem | tsumiki cert inspect
```

### Remote Certificate Fetching

Fetch certificates directly from TLS servers:

```bash
# Fetch from a remote server (default port 443)
tsumiki cert inspect --remote example.com

# Specify a custom port
tsumiki cert inspect --remote example.com:8443
```

**Example:**

```console
$ tsumiki cert inspect --remote github.com -o brief
[0] CN=github.com | Valid: 2026-01-06 to 2026-04-05
[1] C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36 | Valid: 2021-03-22 to 2036-03-21
[2] C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46 | Valid: 2021-03-22 to 2038-01-18
```

### Output Formats

```bash
# Text output (default)
tsumiki cert inspect certificate.pem -o text

# JSON output
tsumiki cert inspect certificate.pem -o json

# YAML output
tsumiki cert inspect certificate.pem -o yaml

# Brief output (one line per certificate)
tsumiki cert inspect certificate.pem -o brief
```

**JSON Example:**

```console
$ tsumiki cert inspect --remote github.com -1 -o json
```

<details>
<summary>Click to see JSON output</summary>

```json
{
  "tbs_certificate": {
    "version": "V3",
    "serial_number": "02:76:56:89:fe:e5:2f:85:c4:c8:a4:76:50:e8:4b:be",
    "signature": {
      "algorithm": "ecdsa-with-SHA256"
    },
    "issuer": {
      "rdn_sequence": [
        {
          "attributes": [
            {
              "attribute_type": "C",
              "attribute_value": "GB"
            }
          ]
        },
        {
          "attributes": [
            {
              "attribute_type": "O",
              "attribute_value": "Sectigo Limited"
            }
          ]
        },
        {
          "attributes": [
            {
              "attribute_type": "CN",
              "attribute_value": "Sectigo Public Server Authentication CA DV E36"
            }
          ]
        }
      ]
    },
    "validity": {
      "not_before": "2026-01-06T00:00:00",
      "not_after": "2026-04-05T23:59:59"
    },
    "subject": {
      "rdn_sequence": [
        {
          "attributes": [
            {
              "attribute_type": "CN",
              "attribute_value": "github.com"
            }
          ]
        }
      ]
    },
    "subject_public_key_info": {
      "algorithm": {
        "algorithm": "ecPublicKey",
        "parameters": "secp256r1"
      },
      "subject_public_key": {
        "bit_length": 520
      }
    },
    "extensions": {
      "basic_constraints": {
        "ca": false,
        "path_len_constraint": null
      },
      "key_usage": {
        "digital_signature": true,
        "content_commitment": false,
        "key_encipherment": false
      },
      "extended_key_usage": {
        "purposes": [
          "1.3.6.1.5.5.7.3.1"
        ]
      },
      "subject_alt_name": {
        "names": ["DNS:github.com", "DNS:www.github.com"]
      }
    }
  }
}
```

</details>

### Display Specific Fields

```console
# Show only subject
$ tsumiki cert inspect --remote github.com -1 --show-subject
Subject: CN=github.com

# Show only issuer
$ tsumiki cert inspect --remote github.com -1 --show-issuer
Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36

# Show validity dates
$ tsumiki cert inspect --remote github.com -1 --show-dates
Not Before: Jan 06 00:00:00 2026 GMT
Not After: Apr 05 23:59:59 2026 GMT

# Show serial number
$ tsumiki cert inspect --remote github.com -1 --show-serial
Serial Number: 02:76:56:89:fe:e5:2f:85:c4:c8:a4:76:50:e8:4b:be

# Show signature and public key algorithms
$ tsumiki cert inspect certificate.pem --show-algorithms
Signature Algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
Public Key Algorithm: ecPublicKey (1.2.840.10045.2.1)

# Show fingerprint (default: SHA256)
$ tsumiki cert inspect certificate.pem --show-fingerprint
SHA256 Fingerprint: ab:cd:ef:01:23:45:67:89:...

# Show fingerprint with specific algorithm
$ tsumiki cert inspect certificate.pem --show-fingerprint --fingerprint-alg sha512
SHA512 Fingerprint: ab:cd:ef:01:23:45:67:89:...

# Show public key in PEM format
$ tsumiki cert inspect certificate.pem --show-pubkey
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----

# Show Subject Alternative Names (SAN)
$ tsumiki cert inspect --remote github.com -1 --show-san
Subject Alternative Names:
  DNS:github.com
  DNS:www.github.com

# Show certificate purposes (Extended Key Usage)
$ tsumiki cert inspect certificate.pem --show-purposes
Certificate Purposes:
  - Server Authentication
  - Client Authentication

# List all extensions
$ tsumiki cert inspect certificate.pem --list-extensions
Extensions:
  X509v3 basicConstraints [2.5.29.19] (critical)
  X509v3 keyUsage [2.5.29.15] (critical)
  X509v3 extendedKeyUsage [2.5.29.37]
  X509v3 subjectAltName [2.5.29.17]
  X509v3 subjectKeyIdentifier [2.5.29.14]
  X509v3 authorityKeyIdentifier [2.5.29.35]
```

### Certificate Chain Options

When working with certificate chains:

```console
# Show only the first certificate (end-entity)
$ tsumiki cert inspect chain.pem -1
$ tsumiki cert inspect chain.pem --first

# Show certificate at specific index (0-indexed)
$ tsumiki cert inspect chain.pem --index 1

# Show only first N certificates
$ tsumiki cert inspect chain.pem --depth 2

# Show only the root certificate (self-signed)
$ tsumiki cert inspect chain.pem --root

# Hide certificate index headers
$ tsumiki cert inspect chain.pem --no-header
```

### Validation Options

```console
# Check if certificate is expired
$ tsumiki cert inspect certificate.pem --check-expiry
Certificate is VALID (expires on 2026-04-05 23:59:59 UTC)

# Check if certificate is self-signed
$ tsumiki cert inspect certificate.pem --check-self-signed
Self-Signed: No
```

### Other Options

```console
# Show OID values instead of human-readable names
$ tsumiki cert inspect certificate.pem --show-oid
```

## DER Operations

### Convert PEM to DER

```console
# Output DER binary
$ tsumiki der inspect certificate.pem > certificate.der

# Output as hex dump
$ tsumiki der inspect certificate.pem --hex
00000000: 30 82 05 3e 30 82 03 26 a0 03 02 01 02 02 10 02  0..>0..&........
00000010: 76 56 89 fe e5 2f 85 c4 c8 a4 76 50 e8 4b be 30  vV.../....vP.K.0
...
```

### Display Hex Dump

```console
# Display hex dump of a DER file
$ tsumiki der dump certificate.der
00000000: 30 82 05 3e 30 82 03 26 a0 03 02 01 02 02 10 02  0..>0..&........
00000010: 76 56 89 fe e5 2f 85 c4 c8 a4 76 50 e8 4b be 30  vV.../....vP.K.0
...
```

### Convert DER to PEM

```console
# Convert DER to PEM (specify label type)
$ tsumiki der encode certificate.der -t certificate
-----BEGIN CERTIFICATE-----
MIIFPjCCAyagAwIBAgIQAnZWif7lL4XEyKR2UOhLvjANBgkqhkiG9w0BAQsFADB7
...
-----END CERTIFICATE-----

$ tsumiki der encode private-key.der -t private-key
$ tsumiki der encode public-key.der -t public-key
```

## ASN.1 Inspection

Display the ASN.1 structure of a file.

### Help Output

```console
$ tsumiki asn1 inspect -h
Inspect DER to ASN.1 structure

Usage: tsumiki asn1 inspect [OPTIONS] [FILE]

Arguments:
  [FILE]  Path to the DER or PEM file. If not specified, reads from stdin

Options:
      --parse-implicit  Try to parse implicit-tagged OCTET STRING content as ASN.1
  -h, --help            Print help
```

### Basic Usage

```console
# Inspect ASN.1 structure (PEM or DER)
$ tsumiki asn1 inspect certificate.pem
$ tsumiki asn1 inspect certificate.der

# Parse implicit-tagged OCTET STRING content as ASN.1
$ tsumiki asn1 inspect certificate.pem --parse-implicit
```

**Example output:**

```text
SEQUENCE {
  SEQUENCE {
    [0] {
      INTEGER 2
    }
    INTEGER 0x027656...
    SEQUENCE {
      OBJECT IDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    }
    SEQUENCE {
      SET {
        SEQUENCE {
          OBJECT IDENTIFIER 2.5.4.6 (C)
          PRINTABLE STRING "GB"
        }
      }
      ...
    }
    SEQUENCE {
      UTC TIME 2026-01-06 00:00:00
      UTC TIME 2026-04-05 23:59:59
    }
    ...
  }
  SEQUENCE {
    OBJECT IDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
  }
  BIT STRING (552 bits)
}
```

## PKCS Key Inspection

Inspect private and public keys in various PKCS formats.

### Help Output

```console
$ tsumiki pkcs inspect -h
Inspect PKCS key from PEM file

Usage: tsumiki pkcs inspect [OPTIONS] [FILE]

Arguments:
  [FILE]  Path to the PEM file. If not specified, reads from stdin

Options:
  -o, --output <OUTPUT>
          Output format (json, yaml, text) [default: text]
      --show-oid
          Show OID instead of name
      --show-fingerprint
          Show fingerprint
      --fingerprint-alg <FINGERPRINT_ALG>
          Fingerprint algorithm (SHA1, SHA256, SHA512) [default: sha256]
      --detailed
          Show detailed information
      --hex
          Show HEX dump of the key data
      --show-pubkey
          Show public key from private key (PEM format)
      --show-key-size
          Show key size information (RSA bit length, EC curve, etc.)
  -h, --help
          Print help
```

### Supported Formats

- PKCS#1 RSA keys (`RSA PRIVATE KEY`, `RSA PUBLIC KEY`)
- PKCS#8 keys (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `PUBLIC KEY`)
- SEC1 EC keys (`EC PRIVATE KEY`)

### Basic Usage

```console
# Inspect a private key
$ tsumiki pkcs inspect private-key.pem

# Inspect a public key
$ tsumiki pkcs inspect public-key.pem
```

### Output Formats

```console
# Text output (default)
$ tsumiki pkcs inspect key.pem -o text

# JSON output
$ tsumiki pkcs inspect key.pem -o json

# YAML output
$ tsumiki pkcs inspect key.pem -o yaml
```

### Display Options

```console
# Show OID instead of algorithm name
$ tsumiki pkcs inspect key.pem --show-oid

# Show fingerprint
$ tsumiki pkcs inspect key.pem --show-fingerprint
SHA256 Fingerprint: ab:cd:ef:01:23:45:67:89:...

# Show fingerprint with specific algorithm
$ tsumiki pkcs inspect key.pem --show-fingerprint --fingerprint-alg sha512

# Show detailed information
$ tsumiki pkcs inspect key.pem --detailed

# Show hex dump of key data
$ tsumiki pkcs inspect key.pem --hex

# Show key size (bits)
$ tsumiki pkcs inspect key.pem --show-key-size
Key Size: 2048 bits

# Extract public key from private key (PEM output)
$ tsumiki pkcs inspect private-key.pem --show-pubkey
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

## Examples

### Inspect a Remote Certificate

```console
$ tsumiki cert inspect --remote github.com -o brief
[0] CN=github.com | Valid: 2026-01-06 to 2026-04-05
[1] C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36 | Valid: 2021-03-22 to 2036-03-21
[2] C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46 | Valid: 2021-03-22 to 2038-01-18
```

### Check Certificate Expiry

```console
$ tsumiki cert inspect --remote example.com --check-expiry
Certificate is VALID (expires on 2025-12-31 23:59:59 UTC)
```

### Extract Public Key from Certificate

```console
$ tsumiki cert inspect certificate.pem --show-pubkey
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

### View ASN.1 Structure of a Key

```console
$ tsumiki asn1 inspect private-key.pem
SEQUENCE {
  INTEGER 0
  SEQUENCE {
    OBJECT IDENTIFIER 1.2.840.113549.1.1.1 (rsaEncryption)
    NULL
  }
  OCTET STRING (contains 1190 bytes)
}
```

### Get Key Size

```console
$ tsumiki pkcs inspect rsa-key.pem --show-key-size
Key Size: 2048 bits

$ tsumiki pkcs inspect ec-key.pem --show-key-size
Key Size: 256 bits
```

### Convert Certificate Chain to JSON

```console
$ tsumiki cert inspect chain.pem -o json > chain.json
```

### Pipe Operations

```console
# Fetch remote cert, extract public key
$ tsumiki cert inspect --remote github.com -1 --show-pubkey > github-pubkey.pem

# Read from stdin
$ cat certificate.pem | tsumiki cert inspect --show-san

# Convert PEM to DER via pipe
$ cat cert.pem | tsumiki der inspect > cert.der
```
