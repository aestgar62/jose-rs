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

#[cfg(feature = "jwk-ecdsa")]
mod ecdsa;
#[cfg(feature = "jwk-eddsa")]
mod eddsa;
#[cfg(feature = "jwk-rsa")]
mod rsa;

#[cfg(feature = "jwk-ecdsa")]
pub use self::ecdsa::ECData;
#[cfg(feature = "jwk-eddsa")]
pub use self::eddsa::OctetKeyPairData;
#[cfg(feature = "jwk-rsa")]
pub use self::rsa::RsaData;

//use ptypes::Base64urlUInt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Key Type (kty) identifies the cryptographic algorithm family used with the key, such as "RSA"
/// or "EC".
///
/// [RFC 7517 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum KeyType {
    #[cfg(feature = "jwk-rsa")]
    /// RSA
    RSA(RsaData),
    /// OKP (Octet Key Pair) - EdDSA
    #[cfg(feature = "jwk-eddsa")]
    OKP(OctetKeyPairData),
}

#[cfg(test)]
mod tests {


}