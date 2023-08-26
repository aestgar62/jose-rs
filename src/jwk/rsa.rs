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

//! # RSA data parameter for JWK
//!
//! [RFC 7518 Section 6.3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1)
//!

#![deny(missing_docs)]

use crate::error::Error;

use ptypes::Base64urlUInt;

use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey, RsaPublicKey,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// RSA Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct RsaData {
    // RSA public key
    /// The modulus value for the RSA public key as a Base64urlUInt- encoded.
    #[serde(rename = "n")]
    pub modulus: Option<Base64urlUInt>,
    /// The exponent value for the RSA public key as a Base64urlUInt- encoded.
    #[serde(rename = "e")]
    pub exponent: Option<Base64urlUInt>,

    // RSA private key
    /// The private exponent value for the RSA private key as a Base64urlUInt- encoded.
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_exponent: Option<Base64urlUInt>,
    /// The first prime factor value for the RSA private key as a Base64urlUInt- encoded.
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_prime_factor: Option<Base64urlUInt>,
    /// The second prime factor value for the RSA key as a Base64urlUInt- encoded.  
    #[serde(rename = "q")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_prime_factor: Option<Base64urlUInt>,
    /// The first factor Chinese Remainder Theorem (CRT) exponent value for the RSA private key as
    /// a Base64urlUInt- encoded.
    #[serde(rename = "dp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_prime_factor_crt_exponent: Option<Base64urlUInt>,
    /// The second factor Chinese Remainder Theorem (CRT) exponent value for the RSA private key as
    /// a Base64urlUInt- encoded.
    #[serde(rename = "dq")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_prime_factor_crt_exponent: Option<Base64urlUInt>,
    /// The first Chinese Remainder Theorem (CRT) coefficient value for the RSA private key as a
    /// Base64urlUInt- encoded.
    #[serde(rename = "qi")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_crt_coefficient: Option<Base64urlUInt>,
    /// The other primes information for the RSA private key.
    #[serde(rename = "oth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_primes_info: Option<Vec<Prime>>,
}

/// Prime for RSA private key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct Prime {
    /// Prime factor
    #[serde(rename = "r")]
    pub prime_factor: Base64urlUInt,
    /// Factor CRT exponent
    #[serde(rename = "d")]
    pub factor_crt_exponent: Base64urlUInt,
    /// Factor CRT coefficient
    #[serde(rename = "t")]
    pub factor_crt_coefficient: Base64urlUInt,
}

impl From<&RsaPublicKey> for RsaData {
    fn from(pk: &rsa::RsaPublicKey) -> Self {
        Self {
            modulus: Some(Base64urlUInt(pk.n().to_bytes_be())),
            exponent: Some(Base64urlUInt(pk.e().to_bytes_be())),
            private_exponent: None,
            first_prime_factor: None,
            second_prime_factor: None,
            first_prime_factor_crt_exponent: None,
            second_prime_factor_crt_exponent: None,
            first_crt_coefficient: None,
            other_primes_info: None,
        }
    }
}

impl TryFrom<&RsaPrivateKey> for RsaData {
    type Error = Error;
    fn try_from(sk: &rsa::RsaPrivateKey) -> Result<Self, Self::Error> {
        use num_bigint::traits::ModInverse;
        use num_traits::identities::One;
        use rsa::BigUint;
        let primes = sk.primes();
        if primes.len() < 2 {
            return Err(Error::RSA("prime numbers are less than two".to_owned()));
        }
        let prime1 = &primes[0];
        let prime2 = &primes[1];
        let dp = sk.d() % (prime1 - BigUint::one());
        let dq = sk.d() % (prime2 - BigUint::one());
        let qi = prime2
            .clone()
            .mod_inverse(prime1.clone())
            .ok_or_else(|| Error::RSA("invalid prime".to_owned()))?
            .to_biguint()
            .ok_or_else(|| Error::RSA("invalid prime".to_owned()))?;
        let mut crt = prime1 * prime2;
        let mut rsa_primes: Vec<Prime> = Vec::new();
        for prime in &primes[2..] {
            let exp = sk.d() % (prime - BigUint::one());
            let coeff = crt
                .clone()
                .mod_inverse(prime)
                .ok_or_else(|| Error::RSA("invalid coefficient".to_owned()))?
                .to_biguint()
                .ok_or_else(|| Error::RSA("invalid prime".to_owned()))?;
            let rsa_prime = Prime {
                prime_factor: Base64urlUInt(prime.to_bytes_be()),
                factor_crt_exponent: Base64urlUInt(exp.to_bytes_be()),
                factor_crt_coefficient: Base64urlUInt(coeff.to_bytes_be()),
            };
            rsa_primes.push(rsa_prime);
            crt *= prime;
        }
        let other = if rsa_primes.is_empty() {
            None
        } else {
            Some(rsa_primes)
        };
        Ok(Self {
            modulus: Some(Base64urlUInt(sk.n().to_bytes_be())),
            exponent: Some(Base64urlUInt(sk.e().to_bytes_be())),
            private_exponent: Some(Base64urlUInt(sk.d().to_bytes_be())),
            first_prime_factor: Some(Base64urlUInt(primes[0].to_bytes_be())),
            second_prime_factor: Some(Base64urlUInt(primes[1].to_bytes_be())),
            first_prime_factor_crt_exponent: Some(Base64urlUInt(dp.to_bytes_be())),
            second_prime_factor_crt_exponent: Some(Base64urlUInt(dq.to_bytes_be())),
            first_crt_coefficient: Some(Base64urlUInt(qi.to_bytes_be())),
            other_primes_info: other,
        })
    }
}

impl TryFrom<&RsaData> for RsaPublicKey {
    type Error = Error;
    fn try_from(data: &RsaData) -> Result<Self, Self::Error> {
        use rsa::BigUint;
        let n = data
            .modulus
            .as_ref()
            .ok_or(Error::RSA("RSA missing public modulus".to_owned()))?;
        let e = data
            .exponent
            .as_ref()
            .ok_or(Error::RSA("RSA missing public exponent".to_owned()))?;
        let pk = Self::new(BigUint::from_bytes_be(&n.0), BigUint::from_bytes_be(&e.0))
            .map_err(|_| Error::RSA("RSA invalid data".to_owned()))?;
        Ok(pk)
    }
}

impl TryFrom<&RsaData> for RsaPrivateKey {
    type Error = Error;
    #[allow(clippy::many_single_char_names)]
    fn try_from(data: &RsaData) -> Result<Self, Self::Error> {
        use rsa::BigUint;
        let n = data
            .modulus
            .as_ref()
            .ok_or(Error::RSA("RSA missing public modulus".to_owned()))?;
        let e = data
            .exponent
            .as_ref()
            .ok_or(Error::RSA("RSA missing public exponent".to_owned()))?;
        let d = data
            .private_exponent
            .as_ref()
            .ok_or(Error::RSA("RSA missing private exponent".to_owned()))?;
        let p = data
            .first_prime_factor
            .as_ref()
            .ok_or(Error::RSA("RSA missing prime".to_owned()))?;
        let q = data
            .second_prime_factor
            .as_ref()
            .ok_or(Error::RSA("RSA missing prime".to_owned()))?;
        let mut primes = vec![BigUint::from_bytes_be(&p.0), BigUint::from_bytes_be(&q.0)];
        for prime in data.other_primes_info.iter().flatten() {
            primes.push(BigUint::from_bytes_be(&prime.prime_factor.0));
        }
        let pk = Self::from_components(
            BigUint::from_bytes_be(&n.0),
            BigUint::from_bytes_be(&e.0),
            BigUint::from_bytes_be(&d.0),
            primes,
        )
        .map_err(|_| Error::RSA("RSA invalid data".to_owned()))?;
        Ok(pk)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use rsa::{RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_rsa_data() {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
        let data = RsaData::try_from(&sk).expect("failed to convert to data");
        let sk2 = RsaPrivateKey::try_from(&data).expect("failed to convert to private key");
        assert_eq!(sk, sk2);
        let pk = RsaPublicKey::try_from(&data).expect("failed to convert to public key");
        let pk2 = sk2.to_public_key();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_rsa_data_with_other_primes() {
        use rsa::BigUint;
        let n = BigUint::from_bytes_be(&[0x00, 0x9d, 0x9e, 0x7d, 0x7c, 0x5a, 0x7a, 0x7d, 0x7d, 0x7d]);
        let e = BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
        let d = BigUint::from_bytes_be(&[0x00, 0x9d, 0x9e, 0x7d, 0x7c, 0x5a, 0x7a, 0x7d, 0x7d, 0x7d]);
        let p1 = BigUint::from_bytes_be(&[0x00, 0x9d, 0x9e, 0x7d, 0x7c, 0x5a, 0x7a, 0x7d, 0x7d, 0x7d]);
        let p2 = BigUint::from_bytes_be(&[0x00, 0x9d, 0x9e, 0x7d, 0x7c, 0x5a, 0x7a, 0x7d, 0x7d, 0x7d]);
        let primes = vec![p1, p2];
        let sk = RsaPrivateKey::from_components(n, e, d, primes).unwrap();
        let data = RsaData::try_from(&sk);
        assert!(data.is_err());
   }
}
