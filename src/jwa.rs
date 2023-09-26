// Copyright 2023 Antonio Estevez <aestevez@opencanarias.es>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing
// permissions and limitations under the License.

//! # Json Web Algorithms (JWA)
//!

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use std::fmt;

/// Enumerated algorithms for use with JSON Web Signature(JWS).
///
/// The values used must either be registered in the IANA "JSON Web Signature and Encryption
/// Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq, Zeroize)]
pub enum SignatureAlgorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256
    PS256,
    /// ECDSA using P-384
    PS384,
    /// ECDSA using P-521
    PS521,
    /// EdDSA using Ed25519
    EdDSA,
    /// EdDSA using Ed25519 with Blake2 256
    EdBlake2b,
    /// ECDSA using P256
    ES256,
    /// ECDSA using P384
    ES384,
    /// ECDSA using secp256k1    
    ES256K,
    /// ECDSA using P256 with Blake2 256
    ESBlake2b,
    /// ECDSA using secp256k1 with Blake2 256
    ESBlake2bK,
    /// ECDSA using secp256k1 SHA2 256
    ES256KR,
    /// ECDSA using secp256k1 with Keccak 256
    ESKeccakKR,
    /// No algorithm
    #[serde(rename = "none", alias = "None")]
    None,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::None
    }
}

/// Enumerated algorithms for use with JSON Web Encryption(JWE).
///
/// The values used must either be registered in the IANA "JSON Web Signature and Encryption
/// Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.
///
/// [RFC7518 Section 4.1](https://tools.ietf.org/html/rfc7518#section-4.1)
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq, Zeroize)]
pub enum JweAlgorithm {
    /// RSA with PKCS1 padding using SHA-1
    RSA1_5,
    /// RSA with OAEP
    #[serde(rename = "RSA-OAEP")]
    RSAOAEP,
    /// RSA with OAEP padding using SHA-1 and MGF1 with SHA-1
    #[serde(rename = "RSA-OAEP-256")]
    RSAOAEP256,
    /// AES Key Wrap with default initial value using 128-bit key
    A128KW,
    /// AES Key Wrap with default initial value using 192-bit key
    A192KW,
    /// AES Key Wrap with default initial value using 256-bit key
    A256KW,
    /// Direct use of a shared symmetric key as the CEK
    #[serde(rename = "dir")]
    Dir,
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDHES,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDHESA128KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDHESA192KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDHESA256KW,
    /// Key wrapping with AES GCM using 128-bit key
    #[serde(rename = "A128GCMKW")]
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key
    #[serde(rename = "A192GCMKW")]
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key
    #[serde(rename = "A256GCMKW")]
    A256GCMKW,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2HS256A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2HS384A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2HS512A256KW,
    /// None algorithm
    #[serde(rename = "none", alias = "None")]
    None,
}

impl JweAlgorithm {
    /// Enumeration values to iterate.
    pub const VALUES: [Self; 6] = [
        Self::RSA1_5,
        Self::RSAOAEP,
        Self::RSAOAEP256,
        Self::A128KW,
        Self::A192KW,
        Self::A256KW,
    ];

    /// When Key Wrapping, Key Encryption, or Key Agreement with Key
    /// Wrapping are employed return false.
    pub fn is_direct(&self) -> bool {
        match self {
            Self::Dir | Self::ECDHES => true,
            _ => false,
        }
    }

    /// When Direct Key Agreement or Key Agreement with Key Wrapping are
    /// employed return true.
    pub fn is_key_agreement(&self) -> bool {
        match self {
            Self::ECDHES | Self::ECDHESA128KW | Self::ECDHESA192KW | Self::ECDHESA256KW => true,
            _ => false,
        }
    }

    /// Key size in bytes or 0 if not applicable.
    pub fn size(&self) -> usize {
        match self {
            Self::RSA1_5 => 32,
            Self::RSAOAEP => 32,
            Self::RSAOAEP256 => 32,
            Self::A128KW => 16,
            Self::A192KW => 24,
            Self::A256KW => 32,
            Self::Dir => 0,
            Self::ECDHES => 16,
            Self::ECDHESA128KW => 16,
            Self::ECDHESA192KW => 24,
            Self::ECDHESA256KW => 32,
            Self::A128GCMKW => 16,
            Self::A192GCMKW => 24,
            Self::A256GCMKW => 32,
            Self::PBES2HS256A128KW => 16,
            Self::PBES2HS384A192KW => 24,
            Self::PBES2HS512A256KW => 32,
            Self::None => 0,
        }
    }
}

impl Default for JweAlgorithm {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for JweAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::RSA1_5 => write!(f, "RSA1_5"),
            Self::RSAOAEP => write!(f, "RSA-OAEP"),
            Self::RSAOAEP256 => write!(f, "RSA-OAEP-256"),
            Self::A128KW => write!(f, "A128KW"),
            Self::A192KW => write!(f, "A192KW"),
            Self::A256KW => write!(f, "A256KW"),
            Self::Dir => write!(f, "dir"),
            Self::ECDHES => write!(f, "ECDH-ES"),
            Self::ECDHESA128KW => write!(f, "ECDH-ES+A128KW"),
            Self::ECDHESA192KW => write!(f, "ECDH-ES+A192KW"),
            Self::ECDHESA256KW => write!(f, "ECDH-ES+A256KW"),
            Self::A128GCMKW => write!(f, "A128GCMKW"),
            Self::A192GCMKW => write!(f, "A192GCMKW"),
            Self::A256GCMKW => write!(f, "A256GCMKW"),
            Self::PBES2HS256A128KW => write!(f, "PBES2-HS256+A128KW"),
            Self::PBES2HS384A192KW => write!(f, "PBES2-HS384+A192KW"),
            Self::PBES2HS512A256KW => write!(f, "PBES2-HS512+A256KW"),
            Self::None => write!(f, "none"),
        }
    }
}

/// Enumerated algorithms for Content Encryption Algorithms for use with JSON Web Encryption(JWE).
///
/// The values used must either be registered in the IANA "JSON Web Signature and Encryption
/// Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.
///
/// [RFC7518 Section 5.1](https://tools.ietf.org/html/rfc7518#section-5.1)
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq, Zeroize)]
pub enum EncryptionAlgorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    /// using a 128 bit key, with HMAC-SHA-256 for authentication
    #[serde(rename = "A128CBC-HS256")]
    A128CBCHS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    /// using a 192 bit key, with HMAC-SHA-384 for authentication
    #[serde(rename = "A192CBC-HS384")]
    A192CBCHS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    /// using a 256 bit key, with HMAC-SHA-512 for authentication
    #[serde(rename = "A256CBC-HS512")]
    A256CBCHS512,
    /// AES in Galois/Counter Mode (GCM) (128 bit key) with 128 bit tag
    A128GCM,
    /// AES in Galois/Counter Mode (GCM) (192 bit key) with 192 bit tag
    A192GCM,
    /// AES in Galois/Counter Mode (GCM) (256 bit key) with 256 bit tag
    A256GCM,
    /// ChaCha20-Poly1305 AEAD algorithm with a 256 bit key and a 96 bit nonce.
    #[serde(rename = "C20P")]
    C20P,
    /// ChaCha20-Poly1305 AEAD algorithm with a 256 bit key and a 192 bit nonce.
    #[serde(rename = "C20P192")]
    C20P192,
    /// ChaCha20-Poly1305 AEAD algorithm with a 256 bit key and a 256 bit nonce.
    #[serde(rename = "C20P256")]
    C20P256,
    /// None algorithm
    #[serde(rename = "none", alias = "None")]
    None,
}

impl EncryptionAlgorithm {
    /// Enumeration values to iterate
    pub const VALUES: [Self; 6] = [
        Self::A128CBCHS256,
        Self::A192CBCHS384,
        Self::A256CBCHS512,
        Self::A128GCM,
        Self::A192GCM,
        Self::A256GCM,
    ];

    /// Get the key size in bytes.
    pub fn size(&self) -> usize {
        match self {
            Self::A128CBCHS256 => 32,
            Self::A192CBCHS384 => 48,
            Self::A256CBCHS512 => 64,
            Self::A128GCM => 16,
            Self::A192GCM => 24,
            Self::A256GCM => 32,
            Self::C20P => 32,
            Self::C20P192 => 24,
            Self::C20P256 => 32,
            Self::None => 0,
        }
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::A128CBCHS256 => write!(f, "A128CBC-HS256"),
            Self::A192CBCHS384 => write!(f, "A192CBC-HS384"),
            Self::A256CBCHS512 => write!(f, "A256CBC-HS512"),
            Self::A128GCM => write!(f, "A128GCM"),
            Self::A192GCM => write!(f, "A192GCM"),
            Self::A256GCM => write!(f, "A256GCM"),
            Self::C20P => write!(f, "C20P"),
            Self::C20P192 => write!(f, "C20P192"),
            Self::C20P256 => write!(f, "C20P256"),
            Self::None => write!(f, "none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm() {
        let alg = SignatureAlgorithm::HS256;
        assert_eq!(alg, SignatureAlgorithm::HS256);
        let alg = SignatureAlgorithm::default();
        assert_eq!(alg, SignatureAlgorithm::None);
    }

    #[test]
    fn test_jwe_algorithm() {
        let alg = JweAlgorithm::RSA1_5;
        assert_eq!(alg, JweAlgorithm::RSA1_5);
        let alg = JweAlgorithm::default();
        assert_eq!(alg, JweAlgorithm::None);
    }

    #[test]
    fn test_encryption_algorithm() {
        let alg = EncryptionAlgorithm::A128CBCHS256;
        assert_eq!(alg, EncryptionAlgorithm::A128CBCHS256);
        let alg = EncryptionAlgorithm::default();
        assert_eq!(alg, EncryptionAlgorithm::None);
    }
}
