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

/// Enumerated algorithms for use with JSON Web Key (JWK).
/// 
/// The values used must either be registered in the IANA "JSON Web Signature and Encryption
/// Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.
/// 
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
pub enum Algorithm {
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
    /// ECDSA using P-256 and SHA-256
    PS256,
    /// ECDSA using P-384 and SHA-384
    PS384,
    /// ECDSA using P-521 and SHA-512
    PS512,
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

impl Default for Algorithm {
    fn default() -> Self {
        Self::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm() {
        let alg = Algorithm::HS256;
        assert_eq!(alg, Algorithm::HS256);
    }
}