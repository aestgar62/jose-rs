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

//! # ECDH Key Agreement.
//! https://tools.ietf.org/html/rfc7518#section-4.6
//!

#![deny(missing_docs)]

use super::{
    JweHeader, Jwk,
};
use crate::{error::Error, jwk::KeyType, jwa::JweAlgorithm};

/// ECDH Key Agreement.
pub fn key_agreement(jwk: &Jwk) -> Result<(Vec<u8>, Jwk), Error> {
    let ec_data = if let KeyType::EC(ec_data) = &jwk.key_type {
        ec_data
    } else {
        return Err(Error::InvalidKey(jwk.key_type.to_string()));
    };
    let curve = ec_data
        .curve
        .as_ref()
        .ok_or(Error::InvalidKey("Missing curve".to_string()))?;
    match curve.as_str() {
        #[cfg(feature = "jwk-k256")]
        "secp256k1" => {
            use k256::{ecdh::EphemeralSecret, PublicKey};
            use rand_core::OsRng;
            let pk = PublicKey::try_from(ec_data)?;
            let secret = EphemeralSecret::random(&mut OsRng);
            let shared_secret = secret.diffie_hellman(&pk);
            let ss_bytes = shared_secret.raw_secret_bytes();
            let public = PublicKey::from(&secret);
            let export_jwk = Jwk::try_from(&public)?;
            Ok((ss_bytes.to_vec(), export_jwk))
        }
        #[cfg(feature = "jwk-p256")]
        "P-256" => {
            use p256::{ecdh::EphemeralSecret, PublicKey};
            use rand_core::OsRng;
            let pk = PublicKey::try_from(ec_data)?;
            let secret = EphemeralSecret::random(&mut OsRng);
            let shared_secret = secret.diffie_hellman(&pk);
            let ss_bytes = shared_secret.raw_secret_bytes();
            let public = PublicKey::from(&secret);
            let export_jwk = Jwk::try_from(&public)?;
            Ok((ss_bytes.to_vec(), export_jwk))
        }
        #[cfg(feature = "jwk-p384")]
        "P-384" => {
            use p384::{ecdh::EphemeralSecret, PublicKey};
            use rand_core::OsRng;
            let pk = PublicKey::try_from(ec_data)?;
            let secret = EphemeralSecret::random(&mut OsRng);
            let shared_secret = secret.diffie_hellman(&pk);
            let ss_bytes = shared_secret.raw_secret_bytes();
            let public = PublicKey::from(&secret);
            let export_jwk = Jwk::try_from(&public)?;
            Ok((ss_bytes.to_vec(), export_jwk))
        }
        _ => Err(Error::UnsupportedEllipticCurve(curve.to_string())),
    }
}

/// Derive Key.
pub fn derive_key(header: &JweHeader, key: &[u8]) -> Result<Vec<u8>, Error> {
    let (size, alg_id) = if header.algorithm == JweAlgorithm::ECDHES {
        (header.encryption.size(), header.encryption.to_string())
    } else {
        (header.algorithm.size(), header.algorithm.to_string())
    };
    
    let alg_len = (alg_id.len() as u32).to_be_bytes();
    let apu = header.agreement_partyuinfo.clone().unwrap_or(String::new());
    let apu_len = (apu.len() as u32).to_be_bytes();
    let apv = header.agreement_partyvinfo.clone().unwrap_or(String::new());
    let apv_len = (apv.len() as u32).to_be_bytes();
    let supp_pub_info = ((size * 8) as u32).to_be_bytes();
    let other_info = [
        &alg_len,
        alg_id.as_bytes(),
        &apu_len,
        apu.as_bytes(),
        &apv_len,
        apv.as_bytes(),
        &supp_pub_info,
    ]
    .concat();
    //let mut derived_key = vec![0u8; size];
    let derived_key = concat_kdf::derive_key::<sha2::Sha256>(key, &other_info, size)
        .map_err(|_| Error::Encode("derive key".to_string()))?;
    Ok(derived_key)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_key_agreement() {
        #[cfg(feature = "jwk-k256")]
        {
            use k256::{ecdh::EphemeralSecret, PublicKey};
            let secret = EphemeralSecret::random(&mut rand_core::OsRng);
            let pk = secret.public_key();
            let jwk = Jwk::try_from(&pk).unwrap();
            let (ss_bytes, export_jwk) = key_agreement(&jwk).unwrap();
            let public = PublicKey::try_from(&export_jwk).unwrap();
            let shared = secret.diffie_hellman(&public);
            let ss_bytes2 = shared.raw_secret_bytes();
            println!("ss_bytes: {}", ss_bytes.len());
            assert_eq!(ss_bytes, ss_bytes2.to_vec());
        }
        #[cfg(feature = "jwk-p256")]
        {
            use p256::{ecdh::EphemeralSecret, PublicKey};
            let secret = EphemeralSecret::random(&mut rand_core::OsRng);
            let pk = secret.public_key();
            let jwk = Jwk::try_from(&pk).unwrap();
            let (ss_bytes, export_jwk) = key_agreement(&jwk).unwrap();
            let public = PublicKey::try_from(&export_jwk).unwrap();
            let shared = secret.diffie_hellman(&public);
            let ss_bytes2 = shared.raw_secret_bytes();
            println!("ss_bytes: {}", ss_bytes.len());
            assert_eq!(ss_bytes, ss_bytes2.to_vec());
        }
        #[cfg(feature = "jwk-p384")]
        {
            use p384::{ecdh::EphemeralSecret, PublicKey};
            let secret = EphemeralSecret::random(&mut rand_core::OsRng);
            let pk = secret.public_key();
            let jwk = Jwk::try_from(&pk).unwrap();
            let (ss_bytes, export_jwk) = key_agreement(&jwk).unwrap();
            let public = PublicKey::try_from(&export_jwk).unwrap();
            let shared = secret.diffie_hellman(&public);
            let ss_bytes2 = shared.raw_secret_bytes();
            println!("ss_bytes: {}", ss_bytes.len());
            assert_eq!(ss_bytes, ss_bytes2.to_vec());
        }
    }

    #[test]
    fn test_derive_key() {
        use crate::jwa::{EncryptionAlgorithm, JweAlgorithm};
        use ptypes::Base64urlUInt;
        let mut header = JweHeader::new(JweAlgorithm::ECDHES, EncryptionAlgorithm::A128GCM);
        header.agreement_partyuinfo = Some("Alice".to_string());
        header.agreement_partyvinfo = Some("Bob".to_string());
        let key = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let dk = derive_key(&header, &key).unwrap();
        let result: [u8; 16] = [
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
        ];
        assert_eq!(dk, result.to_vec());
        let b64_value = Base64urlUInt(dk);
        assert_eq!(b64_value.to_string(), "VqqN6vgjbSBcIijNcacQGg");
    }
}
