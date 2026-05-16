# Roadmap

This document outlines the planned evolution of tsumiki beyond what is already
shipped in the crate. The intent is to make the order of upcoming work and its
dependencies legible to contributors and users.

For the current implementation status (what already works), see the
**Implemented** section of the project [README](../README.md). This document
focuses on what comes next and why.

## Current Status (Summary)

```
[Shipped]
├─ Core traits (Encoder/Decoder) and base crates: der, asn1, pem, pkix-types
├─ X.509 v1/v2/v3 certificate parse and encode
├─ X.509 v3 extensions (17 types: BasicConstraints, KeyUsage, SAN/IAN,
│   AKI/SKI, EKU, AIA/SIA, NameConstraints, CertificatePolicies, PolicyMappings,
│   PolicyConstraints, InhibitAnyPolicy, CRLDistributionPoints, FreshestCRL,
│   SubjectDirectoryAttributes)
├─ Certificate chain handling
├─ PKCS#1 / PKCS#8 / SEC1 keys (parse and encode only — no generation yet)
├─ rustls-pki-types integration
├─ JSON/YAML serde for all public types
└─ CLI: `tsumiki {cert, der, asn1, pkcs} inspect`, TLS remote fetch

[In progress]
└─ Milestone: CRL Support  (Issue #67 library + Issue #68 CLI)
```

What tsumiki can do today around revocation is limited to **reading the
`CRLDistributionPoints` / `FreshestCRL` extensions out of certificates**.
The CRL document itself cannot yet be parsed; that is the in-progress
milestone.

## Milestone Roadmap

```
                                  [Shipped: Cert v3 parse]
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  │                       │                       │
        [In progress: CRL parse]   [Planned: Key gen]      [Planned: OCSP]
        (Issue #67/#68)            (PKCS#1/#8/SEC1)         (RFC 6960)
                  │                       │                       │
                  │                       │                       │
                  └───────────┬───────────┘                       │
                              │                                   │
                  ┌───────────┴────────────────────┐              │
                  ▼                                ▼              │
   [Signature verification]            [Certificate signing]      │
   ※ requires crypto backend           ※ requires crypto backend  │
                  │                                │              │
                  └────────────────┬───────────────┘              │
                                   ▼                              │
                       [Certificate validation]  ◀────────────────┘
                       (chain + revocation + expiry, integrated)
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
            [PKCS#7 / CMS]    [PKCS#12]       [Downstream uses]
            (signed data)      (key+cert bundle) (TLS, mTLS, S/MIME, ...)
```

### M1. CRL Support (in progress)

- **Scope**: Parse and encode `CertificateList` / `TBSCertList` /
  `RevokedCertificate` per [RFC 5280 §5]. CRL-specific extensions (cRLNumber,
  deltaCRLIndicator, issuingDistributionPoint, reasonCode, invalidityDate,
  certificateIssuer). PEM `X509 CRL` label. `tsumiki crl inspect` subcommand.
- **Crypto required**: No.
- **Tracking**: GitHub milestone "CRL Support" (Issues
  [#67](https://github.com/terassyi/tsumiki/issues/67),
  [#68](https://github.com/terassyi/tsumiki/issues/68)).
- **Out of scope (deferred)**: signature verification of the CRL itself,
  delta-CRL merging, indirect-CRL chain traversal.

### M2. Cryptographic Backend (cross-cutting foundation)

- **Scope**: Introduce a `tsumiki-crypto` (working name) abstraction with
  pluggable backends. Cover RSA, ECDSA (P-256/P-384/P-521), Ed25519 for both
  signing and verification. Choose initial adapter (likely `ring` or
  `rustcrypto`).
- **Crypto required**: This *is* the crypto layer.
- **Why next**: Every subsequent milestone that does anything more than parse
  (verification, signing, validation, OCSP responses, CMS, PKCS#12) depends on
  this. Building it as a thin, well-tested skeleton early unblocks parallel
  work on M3–M7.

### M3. Signature Verification

- **Scope**: Verify `signatureValue` over `tbsCertificate` and `tbsCertList`
  using the issuer's public key. Used both standalone and as a building block
  for M5.
- **Crypto required**: Yes (depends on M2).
- **Notes**: Public API on `Certificate` / `CertificateList`, e.g.
  `cert.verify_signature(&issuer_public_key)`. Algorithm-agnostic by
  delegating to the crypto backend.

### M4. OCSP (RFC 6960)

- **Scope**: Parse and encode `OCSPRequest`, `OCSPResponse`, `BasicOCSPResponse`,
  `SingleResponse`. Construct OCSP requests from a certificate, parse stapled
  responses. CLI: `tsumiki ocsp {request, response}` or similar.
- **Crypto required**: Optional for parse-only mode; needed to verify the
  response signature.
- **Relationship with CRL**: `SingleResponse.certStatus.revoked` mirrors
  `RevokedCertificate`. M1's work on time encodings, reason codes, and
  invalidity date carries over directly.

### M5. Certificate Validation (RFC 5280 §6)

- **Scope**: Path validation. Build a chain from an end-entity cert + a trust
  store, verify each signature, check validity periods, name constraints,
  policy constraints, basic-constraints `pathLen`, key usage, and revocation
  via CRL and/or OCSP.
- **Crypto required**: Yes.
- **Depends on**: M1, M2, M3, ideally M4.
- **Notes**: Likely a new `tsumiki-validate` crate or a `validation` module
  under `tsumiki-x509`. Should integrate cleanly with rustls's existing
  verifier interfaces.

### M6. Key Generation

- **Scope**: Generate new RSA / EC / Ed25519 keys in PKCS#1, PKCS#8, and SEC1
  formats. Today these formats are only parseable, not generatable.
- **Crypto required**: Yes (RNG and primitive key generation in M2).
- **Notes**: API should yield both the private-key DER/PEM and a parsed
  `PrivateKey` type ready for downstream use.

### M7. Certificate Signing

- **Scope**: PKCS#10 CSR parse/encode. Mint a new `Certificate` from a CSR or
  from raw fields, sign it with an issuer key. Likewise mint a CRL.
- **Crypto required**: Yes.
- **Depends on**: M2, M6 (to have a private key to sign with).
- **Notes**: This is the largest single milestone in scope — it touches name
  building, extension assembly, serial-number policy, and signing all at once.

### M8. PKCS#7 / CMS (RFC 5652)

- **Scope**: SignedData, EnvelopedData, EncryptedData, DigestedData. Required
  for S/MIME, Authenticode, document signing, time-stamping (RFC 3161),
  and many enterprise PKI workflows.
- **Crypto required**: Yes.
- **Depends on**: M3 (signature verify), M7 (cert/CRL embedding inside
  SignedData).
- **Notes**: ASN.1 here uses `ANY DEFINED BY` extensively — expect some
  enhancements to `tsumiki-asn1` to land alongside.

### M9. PKCS#12 (RFC 7292)

- **Scope**: Parse and emit `.p12` / `.pfx` bundles (private key + cert chain,
  password-protected via PBE/HMAC).
- **Crypto required**: Yes — PBKDF, symmetric cipher, MAC.
- **Depends on**: M2, M6.

## Cross-cutting Concerns

These topics span multiple milestones and may produce their own follow-up work:

- **Error model consolidation**: errors currently fan out per crate and per
  feature. As OCSP and CMS land, the surface needs a cohesion pass.
- **Crypto backend selection**: M2's main design decision. Likely `ring`-first
  with an option to swap in `rustcrypto` for non-`ring` targets.
- **ASN.1 extensions**: M1 will add `ENUMERATED` support to `tsumiki-asn1`. M8
  (CMS) will likely require richer `ANY DEFINED BY` modeling. M9 needs PBE
  parameter structures.
- **CLI growth**: each milestone gains a subcommand
  (`tsumiki crl ...`, `tsumiki ocsp ...`, `tsumiki validate ...`,
  `tsumiki sign ...`, `tsumiki gen ...`). UX consistency with
  `tsumiki cert inspect` is the standing target.
- **Performance / streaming**: CRLs and CMS payloads can be large (10 MB+).
  Up to and including M5, the codebase loads structures fully into memory.
  Streaming variants are a non-blocking later optimization.

## Proposed Short-term Sequencing

After M1 (CRL Support) ships, the recommended order is:

1. **M2 Cryptographic Backend** — narrow first cut, just enough to sign and
   verify a few algorithms. Unblocks several milestones in parallel.
2. **M3 Signature Verification** and **M4 OCSP** in parallel. M3 is small
   once M2 exists; M4 reuses the structural learnings from M1.
3. **M5 Certificate Validation** — synthesizes everything above into the
   first end-to-end revocation-aware verifier.
4. **M6 Key Generation** then **M7 Certificate Signing** — completes the
   "tsumiki can mint a PKI from scratch" story.
5. **M8 PKCS#7 / CMS** and **M9 PKCS#12** — order driven by user demand.

### Why this order over alternatives

- *"Do Certificate Signing first"* — Requires M2 (sign), M3 (verify what you
  just signed), and M6 (the key to sign with). Skipping forward forces all
  three to be built without the integration step (M5) that makes them
  exercise-worthy.
- *"Do CMS / PKCS#7 early"* — High user value but parses without semantic
  verification become misleading. Pulling M3 forward is more useful.
- *"Do OCSP before CRL"* — Possible, but CRL's structure is a strict subset
  of the patterns OCSP uses (revoked certificate entries, revocation reasons,
  invalidity dates). Doing CRL first reduces rework on OCSP.

## Roadmap Management

- Each milestone above corresponds to (or will correspond to) a **GitHub
  Milestone** on the [terassyi/tsumiki](https://github.com/terassyi/tsumiki)
  repository.
- Issues for in-progress milestones are labeled with the relevant crate
  (`x509`, `asn1`, `pem`, `cli`, ...) plus a feature label (`crl`, ...).
- This document is updated when milestone scope, ordering, or status changes
  meaningfully. It is **not** the authoritative source for fine-grained task
  status; that lives on the GitHub Milestone pages and their issues.

[RFC 5280 §5]: https://datatracker.ietf.org/doc/html/rfc5280#section-5
