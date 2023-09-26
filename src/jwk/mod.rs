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

//! # JSON Web Key (JWK)
//!
//! JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
//!

#![deny(missing_docs)]

#[cfg(feature = "jwk-ec")]
mod ecdsa;
#[cfg(feature = "jwk-okp")]
mod okp;
#[cfg(feature = "jwk-rsa")]
mod rsa_jwk;
mod symmetric;

use std::fmt::Display;

#[cfg(feature = "jwk-ec")]
pub use self::ecdsa::ECData;
#[cfg(feature = "jwk-okp")]
pub use self::okp::OctetKeyPairData;
#[cfg(feature = "jwk-rsa")]
pub use self::rsa_jwk::RsaData;
#[cfg(feature = "jwk-oct")]
pub use self::symmetric::SymmetricKeysData;

use crate::{jwa::SignatureAlgorithm, Error};

use ptypes::Base64urlUInt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Key Type (kty) identifies the cryptographic algorithm family used with the key, such as "RSA"
/// or "EC".
///
/// [RFC 7517 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum KeyType {
    /// RSA
    #[cfg(feature = "jwk-rsa")]
    RSA(RsaData),
    /// OKP (Octet Key Pair) - EdDSA
    #[cfg(feature = "jwk-eddsa")]
    #[serde(rename = "okp")]
    OKP(OctetKeyPairData),
    /// EC
    #[cfg(feature = "jwk-ec")]
    EC(ECData),
    /// Symmetric Keys
    #[serde(rename = "oct")]
    OCT(SymmetricKeysData),
}

impl KeyType {
    /// Returns the key type
    pub fn key_type(&self) -> &'static str {
        match self {
            #[cfg(feature = "jwk-rsa")]
            Self::RSA(_) => "RSA",
            #[cfg(feature = "jwk-eddsa")]
            Self::OKP(_) => "okp",
            #[cfg(feature = "jwk-ec")]
            Self::EC(_) => "EC",
            Self::OCT(_) => "oct",
        }
    }
}

impl Default for KeyType {
    fn default() -> Self {
        Self::OCT(SymmetricKeysData::default())
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "jwk-rsa")]
            Self::RSA(_) => write!(f, "RSA"),
            #[cfg(feature = "jwk-eddsa")]
            Self::OKP(_) => write!(f, "OKP"),
            #[cfg(feature = "jwk-ec")]
            Self::EC(_) => write!(f, "EC"),
            Self::OCT(_) => write!(f, "OCT"),
        }
    }
}

/// A `Jwk` is a JSON object that represents a cryptographic key.  The members of the object
/// represent properties of the key, including its value.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct Jwk {
    /// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the
    /// key, such as "RSA" or "EC".
    /// [RFC 7517 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1).
    #[serde(flatten)]
    pub key_type: KeyType,

    /// The "use" (public key use) parameter identifies the intended use of the public key.
    /// [RFC 7517 Section 4.2](https://datatracker.ietf.org/doc/html/rfc7517#section-4.2).
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,

    /// The "key_ops" (key operations) parameter identifies the operation(s) for which the key is
    /// intended to be used.
    /// [RFC 7517 Section 4.3](https://datatracker.ietf.org/doc/html/rfc7517#section-4.3).
    #[serde(rename = "key_ops")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_operations: Option<Vec<String>>,

    /// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.
    /// [RFC 7517 Section 4.4](https://datatracker.ietf.org/doc/html/rfc7517#section-4.4).
    #[serde(rename = "alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<SignatureAlgorithm>,

    /// The "kid" (key ID) parameter is used to match a specific key.  This is used, for instance,
    /// to choose among a set of keys within a JWK Set during key rollover.
    /// [RFC 7517 Section 4.5](https://datatracker.ietf.org/doc/html/rfc7517#section-4.5).
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509
    /// public key certificate or certificate chain [RFC5280].
    /// [RFC 7517 Section 4.6](https://datatracker.ietf.org/doc/html/rfc7517#section-4.6).
    #[serde(rename = "x5u")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// The "x5c" (X.509 Certificate Chain) parameter contains a chain of one or more PKIX
    /// certificates [RFC5280].  The certificate chain is represented as a JSON array of
    /// certificate value strings.  Each string in the array is a base64-encoded (Section 4 of
    /// [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008] PKIX certificate value.
    /// [RFC 7517 Section 4.7](https://datatracker.ietf.org/doc/html/rfc7517#section-4.7).
    #[serde(rename = "x5c")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,

    /// The "x5t" (X.509 Certificate SHA-1 Thumbprint) parameter is a base64url-encoded SHA-1
    /// thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
    /// [RFC 7517 Section 4.8](https://datatracker.ietf.org/doc/html/rfc7517#section-4.8).
    #[serde(rename = "x5t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    /// The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) parameter is a base64url-encoded
    /// SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
    /// [RFC 7517 Section 4.9](https://datatracker.ietf.org/doc/html/rfc7517#section-4.9).
    #[serde(rename = "x5t#S256")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,
}

impl Jwk {
    /// Create a new JWK with RSA Key
    #[cfg(feature = "jwk-rsa")]
    pub fn create_rsa() -> Result<Self, Error> {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let sk = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|_| Error::RSA("failed to generate key".to_owned()))?;
        let data = RsaData::try_from(&sk)?;
        Ok(Self {
            key_type: KeyType::RSA(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with EC Key (P-256)
    #[cfg(feature = "jwk-p256")]
    pub fn create_ec_p256() -> Result<Self, Error> {
        use p256::SecretKey;
        let sk = SecretKey::random(&mut rand::thread_rng());
        let data = ECData::try_from(&sk)?;
        Ok(Self {
            key_type: KeyType::EC(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with EC Key (P-384)
    #[cfg(feature = "jwk-p384")]
    pub fn create_ec_p384() -> Result<Self, Error> {
        use p384::SecretKey;
        let sk = SecretKey::random(&mut rand::thread_rng());
        let data = ECData::try_from(&sk)?;
        Ok(Self {
            key_type: KeyType::EC(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with EC Key (K-256)
    #[cfg(feature = "jwk-k256")]
    pub fn create_ec_k256() -> Result<Self, Error> {
        use k256::SecretKey;
        let sk = SecretKey::random(&mut rand::thread_rng());
        let data = ECData::try_from(&sk)?;
        Ok(Self {
            key_type: KeyType::EC(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with OKP Key (Ed25519)
    #[cfg(feature = "jwk-eddsa")]
    pub fn create_okp_ed25519() -> Result<Self, Error> {
        let data = OctetKeyPairData::create_ed25519();
        Ok(Self {
            key_type: KeyType::OKP(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with Symmetric Key (HMAC using SHA-256)
    #[cfg(feature = "jwk-hmac")]
    pub fn create_oct_hmac256(secret: &[u8]) -> Result<Self, Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mac = Hmac::<Sha256>::new_from_slice(secret)
            .map_err(|_| Error::OCT("HMAC can take key of any size".to_owned()))?;
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let data = SymmetricKeysData::from(bytes.as_slice());
        Ok(Self {
            key_type: KeyType::OCT(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with Symmetric Key (HMAC using SHA-384)
    #[cfg(feature = "jwk-hmac")]
    pub fn create_oct_hmac384(secret: &[u8]) -> Result<Self, Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mac = Hmac::<Sha384>::new_from_slice(secret)
            .map_err(|_| Error::OCT("HMAC can take key of any size".to_owned()))?;
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let data = SymmetricKeysData::from(bytes.as_slice());
        Ok(Self {
            key_type: KeyType::OCT(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with Symmetric Key (HMAC using SHA-512)
    #[cfg(feature = "jwk-hmac")]
    pub fn create_oct_hmac512(secret: &[u8]) -> Result<Self, Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        let mac = Hmac::<Sha512>::new_from_slice(secret)
            .map_err(|_| Error::OCT("HMAC can take key of any size".to_owned()))?;
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let data = SymmetricKeysData::from(bytes.as_slice());
        Ok(Self {
            key_type: KeyType::OCT(data),
            ..Default::default()
        })
    }

    /// Create a new JWK with Symmetric Key.
    #[cfg(feature = "jwk-oct")]
    pub fn create_oct(bytes: &[u8]) -> Result<Self, Error> {
        let data = SymmetricKeysData::from(bytes);
        Ok(Self {
            key_type: KeyType::OCT(data),
            ..Default::default()
        })
    }

    /// Returns the key type
    pub fn key_type(&self) -> &'static str {
        self.key_type.key_type()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[cfg(feature = "jwk-rsa")]
    fn test_jwk_rsa() {
        let jwk = Jwk::create_rsa().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "RSA");
    }

    #[test]
    #[cfg(feature = "jwk-p256")]
    fn test_jwk_ec_p256() {
        let jwk = Jwk::create_ec_p256().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "EC");
    }

    #[test]
    #[cfg(feature = "jwk-p384")]
    fn test_jwk_ec_p384() {
        let jwk = Jwk::create_ec_p384().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "EC");
    }

    #[test]
    #[cfg(feature = "jwk-k256")]
    fn test_jwk_ec_k256() {
        let jwk = Jwk::create_ec_k256().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "EC");
    }

    #[test]
    #[cfg(feature = "jwk-eddsa")]
    fn test_jwk_okp_ed25519() {
        let jwk = Jwk::create_okp_ed25519().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "okp");
    }

    #[test]
    #[cfg(feature = "jwk-hmac")]
    fn test_oct_hmac256() {
        let jwk = Jwk::create_oct_hmac256("secret".as_bytes()).unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "oct");
    }

    #[test]
    #[cfg(feature = "jwk-hmac")]
    fn test_oct_hmac384() {
        let jwk = Jwk::create_oct_hmac384("secret".as_bytes()).unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "oct");
    }

    #[test]
    #[cfg(feature = "jwk-hmac")]
    fn test_oct_hmac512() {
        let jwk = Jwk::create_oct_hmac512("secret".as_bytes()).unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "oct");
    }

    #[test]
    #[cfg(feature = "jwk-oct")]
    fn test_oct() {
        let jwk = Jwk::create_oct("secret".as_bytes()).unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let jwk_de: Jwk = serde_json::from_str(&jwk_json).unwrap();
        assert_eq!(jwk, jwk_de);
        assert_eq!(jwk.key_type(), "oct");
    }
}
