# TLS Context Abstraction Layer: Problem Statement

## Objective

Design a portable C++ API for TLS context configuration that abstracts credential loading, session parameters, and certificate verification across multiple SSL/TLS backend implementations (OpenSSL, wolfSSL, mbedTLS, Schannel, Secure Transport, GnuTLS, BoringSSL, s2n).

## Scope

The abstraction targets the **configuration phase** of TLS—specifically the SSL context object pattern common to all implementations—not the streaming I/O or handshake state machine.

## Core Domain Concepts

### Credential Formats

- **X.509 certificates** — ASN.1 DER-encoded identity certificates, typically PEM-wrapped (Base64 with `-----BEGIN CERTIFICATE-----` armor)
- **Private keys** — PKCS#1 (RSA-specific), PKCS#8 (generic), SEC1 (EC-specific), PEM or DER encoded
- **Certificate chains** — Ordered intermediate CA certificates for path building
- **Trust anchors** — Root CA certificates for peer verification
- **PKCS#12/PFX** — Password-protected binary bundles containing certificate + key + chain

### Protocol Configuration

- **ALPN** — Application-Layer Protocol Negotiation (RFC 7301)
- **SNI** — Server Name Indication (RFC 6066)
- **Ciphersuites** — TLS 1.2 format (e.g., `ECDHE-RSA-AES128-GCM-SHA256`) and TLS 1.3 suites
- **Protocol versions** — Minimum/maximum TLS version bounds (1.2, 1.3)

### Certificate Verification

- **Path building** — Construct chain from leaf to trust anchor, possibly fetching missing intermediates via AIA chasing
- **Signature validation** — Each certificate's signature verified against issuer's public key
- **Validity period** — notBefore ≤ now ≤ notAfter for all certificates in chain
- **Name constraints** — Intermediate CA domain restrictions
- **Key usage / Extended key usage** — Certificate permitted for TLS server/client authentication
- **Hostname matching** — Leaf certificate SAN (or CN fallback) matches requested hostname, including wildcard handling
- **Policy validation** — Certificate policies, mappings, inhibit flags (RFC 5280)
- **SCT validation** — Certificate Transparency proof checking (RFC 6962)

### Revocation Checking

- **CRL** — Certificate Revocation Lists; URL in CRL Distribution Points extension; potentially large, infrequent refresh
- **OCSP** — Online Certificate Status Protocol; URL in Authority Information Access extension; per-certificate, smaller responses, shorter validity windows
- **OCSP stapling** — Server-side: attach pre-fetched OCSP response to handshake (RFC 6066 status_request); Client-side: require stapled response

### Platform Keystores

- **Windows Certificate Store** — System-managed trust anchors and credentials
- **macOS Keychain** — SecIdentityRef, SecCertificateRef
- **PKCS#11** — HSM token interface

## Verification Architecture

### Division of Responsibility

| Task | Responsibility |
|------|----------------|
| Parse certificates, extract AIA/CRL/OCSP URLs | Library helpers or application |
| HTTP fetch of CRL/OCSP/intermediate certs | Application (requires HTTP client) |
| Parse CRL/OCSP responses | TLS library |
| Cryptographic signature validation | TLS library |
| Path building and policy evaluation | TLS library |
| Cache management and refresh scheduling | Application |

### Bootstrap Model

Initial TLS connections rely on **system trust stores** (pre-installed root CAs) with revocation checking disabled or soft-fail. This provides the trusted channel needed to fetch revocation data for stricter subsequent validation:

```
Bootstrap connection:
  Trust store: system default
  Revocation: disabled or soft-fail
  → Sufficient for OAuth flows, OCSP fetches, CRL downloads

Hardened connection (optional):
  Trust store: system or custom
  Revocation: enforced using pre-fetched data
```

## Required Operations

### Credential Loading

| Operation | Input Types |
|-----------|-------------|
| Load entity certificate | PEM blob, DER blob, file path |
| Load private key | PEM/DER blob, file path, optional passphrase |
| Load certificate chain | PEM blob (concatenated), file path |
| Set trust anchors | PEM/DER blob, file path, directory, system default |
| Load PKCS#12 bundle | Binary blob, file path, passphrase |

### Protocol Configuration

| Operation | Input Types |
|-----------|-------------|
| Configure ALPN | Ordered list of protocol strings |
| Set protocol version range | Min/max version enum |
| Set ciphersuites | String (OpenSSL format) or list |
| Role designation | Client context vs server context |

### Verification Configuration

| Operation | Input Types |
|-----------|-------------|
| Set verification mode | Enum: none, peer, require_peer |
| Set verification callback | User-defined chain validation hook |
| Set hostname for matching | String (client-side SNI and cert matching) |

### Revocation Configuration

| Operation | Input Types |
|-----------|-------------|
| Add CRL | DER blob, file path |
| Set OCSP staple (server) | DER blob, file path, refresh callback |
| Require OCSP staple (client) | Boolean or policy enum |
| Set revocation policy | Enum: disabled, soft_fail, hard_fail |

## Backend Mapping

| Backend | Context Object | Cert Loading | Verification | Revocation |
|---------|----------------|--------------|--------------|------------|
| OpenSSL/BoringSSL | `SSL_CTX` | `SSL_CTX_use_certificate` | `SSL_CTX_set_verify` + `X509_STORE` | `X509_STORE_add_crl`, `SSL_CTX_set_tlsext_status_*` |
| wolfSSL | `WOLFSSL_CTX` | OpenSSL-compatible shim | `wolfSSL_CTX_set_verify` | `wolfSSL_CTX_EnableOCSPStapling` |
| mbedTLS | `mbedtls_ssl_config` | `mbedtls_x509_crt_parse` | `mbedtls_x509_crt_verify` | `mbedtls_x509_crl_parse` |
| GnuTLS | `gnutls_certificate_credentials_t` | `gnutls_certificate_set_x509_key_mem` | `gnutls_certificate_verify_peers` | `gnutls_certificate_set_ocsp_status_request_file` |
| Schannel | `SCH_CREDENTIALS` | In-memory `HCERTSTORE` | Automatic via Windows crypto | `SCH_CRED_REVOCATION_CHECK_*` flags |
| Secure Transport | `SSLContextRef` | Keychain or `SecIdentityRef` | Automatic via macOS trust evaluation | System-managed |
| s2n | `s2n_config` | `s2n_config_add_cert_chain_and_key` | `s2n_config_set_verification_ca_location` | Limited |

## Out of Scope

- Connection-level state (handshake, read/write, shutdown)
- Async I/O integration and completion models
- Session resumption and ticket management
- Client certificate request/selection callbacks (server-side mutual TLS negotiation)
- HTTP fetching of revocation data (application responsibility, but may be provided as separate component)

## Search Terms

```
portable TLS abstraction API
SSL context wrapper library
X.509 credential loading interface
cross-platform TLS configuration
backend-agnostic SSL library
TLS provider abstraction C++
certificate verification abstraction
OCSP stapling API design
CRL distribution points fetching
```

## Prior Art

- Boost.Beast/Boost.Asio SSL (OpenSSL-only, interface patterns)
- libcurl TLS backend abstraction
- Qt Network SSL abstraction (`QSslConfiguration`)
- Rust `native-tls` and `rustls` crates
- Go `crypto/tls.Config`
- .NET `SslStream` / `SslClientAuthenticationOptions`
- Python `ssl.SSLContext`