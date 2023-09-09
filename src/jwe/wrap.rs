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

//! # Wrap and Unwrap keys.
//!

#![deny(missing_docs)]

use super::JweHeader;
use crate::{
    jwa::JweAlgorithm,
    jwk::{Jwk, KeyType},
    Error,
};

#[cfg(feature = "jwk-rsa")]
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[cfg(feature = "jwk-rsa")]
use sha2::Sha256;

/// Wrap Content Encryption Key (CEK).
pub fn wrap_cek(header: &JweHeader, jwk: &Jwk, key: &[u8]) -> Result<Vec<u8>, Error> {
    match header.algorithm {
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSA1_5 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                Ok(pk
                    .encrypt(&mut rng, Pkcs1v15Encrypt, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSA1_5.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                let padding = Oaep::new::<Sha256>();
                Ok(pk
                    .encrypt(&mut rng, padding, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSAOAEP.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP256 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha1::Sha1;
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                let padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
                Ok(pk
                    .encrypt(&mut rng, padding, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSAOAEP256.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW => {
            use super::aes::wrap_aes_kw;
            use ::aes::Aes128;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 16 {
                    Err(Error::InvalidKey("Invalid Key size for A128KW".to_string()))
                } else {
                    Ok(wrap_aes_kw::<Aes128>(key, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A192KW => {
            use super::aes::wrap_aes_kw;
            use ::aes::Aes192;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 24 {
                    Err(Error::InvalidKey("Invalid Key size for A128KW".to_string()))
                } else {
                    Ok(wrap_aes_kw::<Aes192>(key, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A256KW => {
            use super::aes::wrap_aes_kw;
            use ::aes::Aes256;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 32 {
                    Err(Error::InvalidKey("Invalid Key size for A128KW".to_string()))
                } else {
                    Ok(wrap_aes_kw::<Aes256>(key, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        _ => Err(Error::UnimplementedAlgorithm(header.algorithm.to_string())),
    }
}

/// Unwrap Content Encryption Key (CEK).
pub fn unwrap_cek(header: &JweHeader, jwk: &Jwk, cek: &[u8]) -> Result<Vec<u8>, Error> {
    match header.algorithm {
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSA1_5 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                Ok(sk
                    .decrypt(Pkcs1v15Encrypt, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSA1_5.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                let padding = Oaep::new::<Sha256>();
                Ok(sk
                    .decrypt(padding, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSAOAEP.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP256 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha1::Sha1;
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                let padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
                Ok(sk
                    .decrypt(padding, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSAOAEP256.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW => {
            use super::aes::unwrap_aes_kw;
            use ::aes::Aes128;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 16 {
                    Err(Error::InvalidKey("Invalid Key size for A128KW".to_string()))
                } else {
                    Ok(unwrap_aes_kw::<Aes128>(cek, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A192KW => {
            use super::aes::unwrap_aes_kw;
            use ::aes::Aes192;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 24 {
                    Err(Error::InvalidKey("Invalid Key size for A192KW".to_string()))
                } else {
                    Ok(unwrap_aes_kw::<Aes192>(cek, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A256KW => {
            use super::aes::unwrap_aes_kw;
            use ::aes::Aes256;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                if kw.len() != 32 {
                    Err(Error::InvalidKey("Invalid Key size for A256KW".to_string()))
                } else {
                    Ok(unwrap_aes_kw::<Aes256>(cek, &kw)?)
                }
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        _ => Err(Error::UnimplementedAlgorithm(header.algorithm.to_string())),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::jwa::JweAlgorithm;

    #[test]
    fn test_wrap_unwrap_cek() {
        use crate::jwk::Jwk;

        let msg = b"0123456789abcdef0123456789abcdef";

        let kp = Jwk::create_rsa().unwrap();
        let mut header = JweHeader {
            algorithm: JweAlgorithm::RSA1_5,
            ..Default::default()
        };

        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        header.algorithm = JweAlgorithm::RSAOAEP;
        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        header.algorithm = JweAlgorithm::RSAOAEP256;
        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A128KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        let mut bytes = [0u8; 24];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A192KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A256KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());
    }
}
