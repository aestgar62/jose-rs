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

//! # EdDSA data parameter for JWK
//!

#![deny(missing_docs)]

use crate::error::Error;

use ptypes::Base64urlUInt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// EdDSA Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct OctetKeyPairData {
    /// The curve name.
    #[serde(rename = "crv")]
    pub curve: String,
    /// The public key value for the EdDSA key as a Base64urlUInt- encoded.
    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,
    /// The private key value for the EdDSA key as a Base64urlUInt- encoded.
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Base64urlUInt>,
}

impl OctetKeyPairData {
    /// Create a new EdDSA key pair
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        Self {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(pk.to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(sk.to_bytes().to_vec())),
        }
    }
}

impl Default for OctetKeyPairData {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&SigningKey> for OctetKeyPairData {
    fn from(sk: &SigningKey) -> Self {
        let pk = sk.verifying_key();
        Self {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(pk.to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(sk.to_bytes().to_vec())),
        }
    }
}

impl From<&VerifyingKey> for OctetKeyPairData {
    fn from(pk: &VerifyingKey) -> Self {
        Self {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(pk.to_bytes().to_vec()),
            private_key: None,
        }
    }
}

impl TryFrom<&OctetKeyPairData> for VerifyingKey {
    type Error = Error;
    fn try_from(data: &OctetKeyPairData) -> Result<Self, Self::Error> {
        if data.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(format!(
                "Curve {} not implemented",
                data.curve
            )));
        }
        Self::try_from(data.public_key.0.as_slice())
            .map_err(|_| Error::OKP("Public key from OctectKeyPairData".to_owned()))
    }
}

impl TryFrom<&OctetKeyPairData> for SigningKey {
    type Error = Error;
    fn try_from(data: &OctetKeyPairData) -> Result<Self, Self::Error> {
        if data.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(format!(
                "Curve {} not implemented",
                data.curve
            )));
        }
        let sk = data
            .private_key
            .as_ref()
            .ok_or(Error::OKP("Missing private key".to_owned()))?;
        Self::try_from(sk.0.as_slice())
            .map_err(|_| Error::OKP("Private key from OctectKeyPairData".to_owned()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_octet_key_pair_data() {
        let okp = OctetKeyPairData::new();
        let pk = VerifyingKey::try_from(&okp).unwrap();
        let sk = SigningKey::try_from(&okp).unwrap();
        let okp2 = OctetKeyPairData::from(&sk);
        let pk2 = VerifyingKey::try_from(&okp2).unwrap();
        let sk2 = SigningKey::try_from(&okp2).unwrap();
        assert_eq!(okp, okp2);
        assert_eq!(pk, pk2);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        let okp3 = OctetKeyPairData::from(&pk);
        let sk3 = SigningKey::try_from(&okp3);
        assert!(sk3.is_err());
    }

    #[test]
    fn test_curve_not_implemented() {
        let mut okp = OctetKeyPairData::new();
        okp.curve = "XX".to_owned();
        let pk = VerifyingKey::try_from(&okp);
        assert!(pk.is_err());
        let sk = SigningKey::try_from(&okp);
        assert!(sk.is_err());
    }

    #[test]
    fn test_invalid_keys() {
        let mut okp = OctetKeyPairData::new();
        okp.private_key = Some(Base64urlUInt(vec![0x00]));
        let sk = SigningKey::try_from(&okp);
        assert!(sk.is_err());
        okp.public_key = Base64urlUInt(vec![0x00]);
        let pk = VerifyingKey::try_from(&okp);
        assert!(pk.is_err());
    }
}
