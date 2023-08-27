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

//! # ECDSA data parameter for JWK
//!

#![deny(missing_docs)]

use crate::error::Error;

use ptypes::Base64urlUInt;

use elliptic_curve::{PublicKey, SecretKey, CurveArithmetic, sec1::ToEncodedPoint};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// ECDSA Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct ECData {
    // Elliptic Curve Public Key.
    #[serde(rename = "crv")]
	/// The curve name.
    pub curve: Option<String>,
	/// The public key `x`value for the ECDSA key as a Base64urlUInt- encoded.
    #[serde(rename = "x")]
    pub x_coordinate: Option<Base64urlUInt>,
	/// The public key `y`value for the ECDSA key as a Base64urlUInt- encoded.
    #[serde(rename = "y")]
    pub y_coordinate: Option<Base64urlUInt>,

    // Elliptic Curve Private Key.
	/// The private key value for the ECDSA key as a Base64urlUInt- encoded.
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec_private_key: Option<Base64urlUInt>,
}

impl ECData {

	/// Create a new ECDSA key pair
	pub fn from_key_pair<C: CurveArithmetic>(curve: &str, sk: SecretKey<C>, pk: PublicKey<C>) -> Result<Self, Error>{
		unimplemented!()
	}
}

// Secp256k1 curve

impl TryFrom<&k256::PublicKey> for ECData {
    type Error = Error;
    fn try_from(pk: &k256::PublicKey) -> Result<Self, Self::Error> {
        use elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        let x = ec_points
            .x()
            .ok_or_else(|| Error::EC("Missing point x".to_owned()))?;
        let y = ec_points
            .y()
            .ok_or_else(|| Error::EC("Missing point y".to_owned()))?;
        Ok(Self {
            curve: Some("secp256k1".to_owned()),
            x_coordinate: Some(Base64urlUInt(x.to_vec())),
            y_coordinate: Some(Base64urlUInt(y.to_vec())),
            ec_private_key: None,
        })
    }
}

impl TryFrom<&ECData> for k256::SecretKey {
    type Error = Error;
    fn try_from(data: &ECData) -> Result<Self, Self::Error> {
        let curve = data.curve.as_ref().ok_or(Error::EC("Missing curve".to_owned()))?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let private_key = data
            .ec_private_key
            .as_ref()
            .ok_or(Error::EC("Missing Secp256k1 Private Key".to_owned()))?;
        let secret_key = k256::SecretKey::from_slice(&private_key.0)
            .map_err(|_| Error::EC("Invalid Secp256k1 Private Key".to_owned()))?;
        Ok(secret_key)
    }
}

impl TryFrom<&ECData> for k256::PublicKey {
    type Error = Error;
    fn try_from(data: &ECData) -> Result<Self, Self::Error> {
        use elliptic_curve::sec1::FromEncodedPoint;
		use elliptic_curve::generic_array::GenericArray;
        use k256::EncodedPoint;
        let x = data
            .x_coordinate
            .as_ref()
            .map_or(vec![], |value| value.0.clone());
        let y = data
            .y_coordinate
            .as_ref()
            .map_or(vec![], |value| value.0.clone());
        let ep = EncodedPoint::from_affine_coordinates(
            &GenericArray::clone_from_slice(&x),
            &GenericArray::clone_from_slice(&y),
            false,
        );
        let opt = k256::PublicKey::from_encoded_point(&ep);
        if bool::from(opt.is_some()) {
            Ok(opt.unwrap())
        } else {
            Err(Error::EC("Invalid Secp256 Public Key".to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	fn test_ecdata_secp256k1() {
		let sk = k256::SecretKey::random(&mut rand::thread_rng());
		let pk = sk.public_key();
		let data = ECData::try_from(&pk).unwrap();
		let pk2 = k256::PublicKey::try_from(&data).unwrap();
		assert_eq!(pk, pk2);
		let sk2 = k256::SecretKey::try_from(&data).unwrap();
		assert_eq!(sk, sk2);
	}
}