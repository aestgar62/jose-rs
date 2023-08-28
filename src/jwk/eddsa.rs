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

    /// From key pair
    pub fn from_keypair(sk: SigningKey, pk: VerifyingKey) -> Self {
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

impl From<VerifyingKey> for OctetKeyPairData {
    fn from(pk: VerifyingKey) -> Self {
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
        let sk = SigningKey::from_bytes(&[
            0x2a, 0x1c, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0a, 0x1b, 0x2c, 0x3d,
            0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
            0x8c, 0x9d, 0x0a, 0x1b,
        ]);
        let pk = sk.verifying_key();
        let okp = OctetKeyPairData::from(pk);
        assert_eq!(okp.curve, "Ed25519");
    }

    #[test]
    fn test_octet_key_pair_data_from_keypair() {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        let okp = OctetKeyPairData::from_keypair(sk.clone(), pk);
        assert_eq!(okp.curve, "Ed25519");
        let sk2 = SigningKey::try_from(&okp).expect("failed to convert to private key");
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        let pk2 = VerifyingKey::try_from(&okp).expect("failed to convert to public key");
        assert_eq!(pk, pk2);
    }
}
