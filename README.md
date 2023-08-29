# jose-rs

[![Rust](https://img.shields.io/badge/Rust-v1.66.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/aestgar62/jose-rs/blob/v0.1.0/LICENSE)
![Build & Test](https://github.com/aestgar62/jose-rs/actions/workflows/build.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/aestgar62/jose-rs/badge.svg?branch=main)](https://coveralls.io/github/aestgar62/jose-rs?branch=main)

Javascript Object Encryption and Signing (JOSE) Library for Rust Language

## Introduction

This library is a Rust implementation of the Javascript Object Signing and Encryption (JOSE) standard. It is intended to be used as a building block for other libraries and applications that need to implement JOSE. It is not intended to be used directly by end users.

## Supported specifications

- [RFC 7515](https://tools.ietf.org/html/rfc7515) - JSON Web Signature (JWS)
- [RFC 7516](https://tools.ietf.org/html/rfc7516) - JSON Web Encryption (JWE)
- [RFC 7517](https://tools.ietf.org/html/rfc7517) - JSON Web Key (JWK)
- [RFC 7518](https://tools.ietf.org/html/rfc7518) - JSON Web Algorithms (JWA)
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)

## JWS Support

TBD.

## JWE Support

TBD.

## JWK Support

- RSA Keys (Rivest-Shamir-Adleman)
- EC Keys (Elliptic Curve Cryptography, including P-256, P-384, P-521 and secp256k1)
- Octet Keys (Symmetric Keys including AES, HMAC, ChaCha20, Poly1305, XChaCha20, XChaCha20-Poly1305)
- OKP Keys (Octet Key Pair, including Ed25519, X25519, and PQC like Dililthium and Kyber)

## JWA Support

- RSA Signatures (RS256, RS384, RS512, PS256, PS384, PS512)
- EC Signatures (ES256, ES384, ES512, EdDSA)
- HMAC Signatures (HS256, HS384, HS512)

## JWT Support

TBD.

## License

This project is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)).
