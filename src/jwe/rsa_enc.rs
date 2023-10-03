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

//! RSA Key Wrapping.
//! https://tools.ietf.org/html/rfc7518#section-4.2
//! https://tools.ietf.org/html/rfc7518#section-4.3
//!

use super::{JweHeader, KeyWrapOrEncrypt};

use crate::{
    jwa::JweAlgorithm,
    jwk::{Jwk, KeyType},
    Error,
};

use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

/// RSA Key Wrapper.
pub struct RsaEncrypt;

impl KeyWrapOrEncrypt for RsaEncrypt {
    fn wrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::RSA(key_data) = &jwk.key_type {
            key_data
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let wk = match header.algorithm {
            JweAlgorithm::RSA1_5 => {
                let key = RsaPublicKey::try_from(key)?;
                key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, cek)
                    .map_err(|_| Error::Encrypt("RSA1_5".to_string()))?
            }
            JweAlgorithm::RSAOAEP => {
                let key = RsaPublicKey::try_from(key)?;
                let padding = Oaep::new::<sha1::Sha1>();
                key.encrypt(&mut rand::thread_rng(), padding, cek)
                    .map_err(|_| Error::Encrypt("RSA_OAEP".to_string()))?
            }
            JweAlgorithm::RSAOAEP256 => {
                let key = RsaPublicKey::try_from(key)?;
                let padding = Oaep::new::<sha2::Sha256>();
                key.encrypt(&mut rand::thread_rng(), padding, cek)
                    .map_err(|_| Error::Encrypt("RSA_OAEP_256".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(header.algorithm.to_string())),
        };
        header.jwk = Some(jwk.clone().public());
        Ok(wk)
    }

    fn unwrap_key(header: &mut JweHeader, wk: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let public_key = jwk.clone().public();
        if header.jwk != Some(public_key) {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        }
        let key = if let KeyType::RSA(key_data) = &jwk.key_type {
            key_data
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let uk = match header.algorithm {
            JweAlgorithm::RSA1_5 => {
                let key = RsaPrivateKey::try_from(key)?;
                key.decrypt(Pkcs1v15Encrypt, wk)
                    .map_err(|_| Error::Decrypt("RSA1_5".to_string()))?
            }
            JweAlgorithm::RSAOAEP => {
                let key = RsaPrivateKey::try_from(key)?;
                let padding = Oaep::new::<sha1::Sha1>();
                key.decrypt(padding, wk)
                    .map_err(|_| Error::Decrypt("RSA_OAEP".to_string()))?
            }
            JweAlgorithm::RSAOAEP256 => {
                let key = RsaPrivateKey::try_from(key)?;
                let padding = Oaep::new::<sha2::Sha256>();
                key.decrypt(padding, wk)
                    .map_err(|_| Error::Decrypt("RSA_OAEP_256".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(header.algorithm.to_string())),
        };
        Ok(uk)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_wrap_key() {
        let mut header = JweHeader::new(JweAlgorithm::RSA1_5, Default::default());
        let jwk = Jwk::create_rsa().unwrap();
        let jwk_err = Jwk::create_oct(b"0123456789abcdef").unwrap();
        let cek = vec![0u8; 32];
        let wk = RsaEncrypt::wrap_key(&mut header, &cek, &jwk).unwrap();
        let uk = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek, uk);
        let wk_err = RsaEncrypt::wrap_key(&mut header, &cek, &jwk_err);
        assert!(wk_err.is_err());
        let uk_err = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk_err);
        assert!(uk_err.is_err());
        header.algorithm = JweAlgorithm::RSAOAEP;
        let wk = RsaEncrypt::wrap_key(&mut header, &cek, &jwk).unwrap();
        let uk = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek, uk);
        let wk_err = RsaEncrypt::wrap_key(&mut header, &cek, &jwk_err);
        assert!(wk_err.is_err());
        let uk_err = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk_err);
        assert!(uk_err.is_err());
        header.algorithm = JweAlgorithm::RSAOAEP256;
        let wk = RsaEncrypt::wrap_key(&mut header, &cek, &jwk).unwrap();
        let uk = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek, uk);
        let wk_err = RsaEncrypt::wrap_key(&mut header, &cek, &jwk_err);
        assert!(wk_err.is_err());
        let uk_err = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk_err);
        assert!(uk_err.is_err());
        header.algorithm = JweAlgorithm::None;
        let wk_err = RsaEncrypt::wrap_key(&mut header, &cek, &jwk);
        assert!(wk_err.is_err());
        let uk_err = RsaEncrypt::unwrap_key(&mut header, &wk, &jwk);
        assert!(uk_err.is_err());
    }
}
