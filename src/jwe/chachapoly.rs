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

//! ChaCha20-Poly1305 key wrapping algorithms and encryption algorithms.
//! https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha-02
//!

#![deny(missing_docs)]

use super::{JweAlgorithm, JweEncryption, JweHeader, KeyWrapOrEncrypt};

use crate::{
    jwa::EncryptionAlgorithm,
    jwk::{Jwk, KeyType},
    Error,
};

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
};

use zeroize::Zeroize;

/// ChaCha20-Poly1305 Encryptor.
/// https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha-02#section-4.1
#[derive(Clone, Debug, Zeroize)]
pub struct ChachaPolyEncrytor {
    /// Encryption algorithm.
    alg: EncryptionAlgorithm,
    /// AES key.
    pub key: Vec<u8>,
    /// AES initialization vector.
    pub iv: Vec<u8>,
}

impl ChachaPolyEncrytor {
    /// Create a new ChaCha20-Poly1305 Encryptor.
    pub fn new(alg: EncryptionAlgorithm, cek: &[u8]) -> Result<Self, Error> {
        match alg {
            EncryptionAlgorithm::C20P => {
                let iv = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                Ok(Self {
                    alg,
                    key: cek.to_vec(),
                    iv: iv.to_vec(),
                })
            }
            EncryptionAlgorithm::XC20P => {
                let iv = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                Ok(Self {
                    alg,
                    key: cek.to_vec(),
                    iv: iv.to_vec(),
                })
            }
            _ => Err(Error::InvalidAlgorithm(alg.to_string())),
        }
    }
}

impl JweEncryption for ChachaPolyEncrytor {
    fn from_slice(alg: EncryptionAlgorithm, cek: &[u8], iv: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if cek.len() != 32 {
            return Err(Error::InvalidKey("key size != 32".to_string()));
        }
        match alg {
            EncryptionAlgorithm::C20P => {
                if iv.len() != 12 {
                    return Err(Error::InvalidKey("iv size != 12".to_string()));
                }
                Ok(Self {
                    alg,
                    key: cek.to_vec(),
                    iv: iv.to_vec(),
                })
            }
            EncryptionAlgorithm::XC20P => {
                if iv.len() != 24 {
                    return Err(Error::InvalidKey("iv size != 24".to_string()));
                }
                Ok(Self {
                    alg,
                    key: cek.to_vec(),
                    iv: iv.to_vec(),
                })
            }
            _ => Err(Error::InvalidAlgorithm(alg.to_string())),
        }
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let mut ciphertext = match self.alg {
            EncryptionAlgorithm::C20P => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                let nonce = Nonce::from_slice(&self.iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("ChaCha20-Poly1305 encrypt".to_string()))?
            }
            EncryptionAlgorithm::XC20P => {
                let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                let nonce = XNonce::from_slice(&self.iv);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("XChaCha20-Poly1305 encrypt".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(self.alg.to_string())),
        };
        let ct_len = ciphertext.len() - 16;
        let tag = ciphertext.split_off(ct_len);
        Ok((ciphertext, tag))
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8], at: &[u8]) -> Result<Vec<u8>, Error> {
        let ciphertext = [ciphertext, at].concat();
        let payload = Payload {
            msg: &ciphertext,
            aad,
        };
        match self.alg {
            EncryptionAlgorithm::C20P => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                let nonce = Nonce::from_slice(&self.iv);
                Ok(cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("ChaCha20-Poly1305 decrypt".to_string()))?)
            }
            EncryptionAlgorithm::XC20P => {
                let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                let nonce = XNonce::from_slice(&self.iv);
                Ok(cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("XChaCha20-Poly1305 decrypt".to_string()))?)
            }
            _ => Err(Error::InvalidAlgorithm(self.alg.to_string())),
        }
    }
}

/// ChaCha20-Poly1305 Key Wrap.
pub struct ChachaPolyKeyWrap;

impl KeyWrapOrEncrypt for ChachaPolyKeyWrap {
    fn wrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let alg = jwe_to_enc(&header.algorithm)?;
        let enc = ChachaPolyEncrytor::new(alg, key)?;
        header.initialization_vector = Some(ptypes::Base64urlUInt(enc.iv.clone()));
        let (ciphertext, tag) = enc.encrypt(cek, &[])?;
        header.authentication_tag = Some(ptypes::Base64urlUInt(tag));
        Ok(ciphertext)
    }

    fn unwrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let iv = header
            .initialization_vector
            .as_ref()
            .ok_or(Error::InvalidAlgorithm(
                "missing initialization vector".to_string(),
            ))?;
        let alg = jwe_to_enc(&header.algorithm)?;
        let enc = ChachaPolyEncrytor::from_slice(alg, key, &iv.0)?;
        let tag = header
            .authentication_tag
            .as_ref()
            .ok_or(Error::InvalidAlgorithm(
                "missing authentication tag".to_string(),
            ))?;
        enc.decrypt(cek, &[], &tag.0)
    }
}

/// From JweAlgorithm to EncryptionAlgorithm.
fn jwe_to_enc(alg: &JweAlgorithm) -> Result<EncryptionAlgorithm, Error> {
    match alg {
        JweAlgorithm::C20PKW | JweAlgorithm::ECDHESC20PKW => Ok(EncryptionAlgorithm::C20P),
        JweAlgorithm::XC20PKW | JweAlgorithm::ECDHESXC20PKW => Ok(EncryptionAlgorithm::XC20P),
        _ => Err(Error::InvalidAlgorithm(alg.to_string())),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_chachapoly_encryption() {
        let mut buffer = vec![0u8; 32];
        getrandom::getrandom(&mut buffer).unwrap();
        let alg = EncryptionAlgorithm::C20P;
        let enc = ChachaPolyEncrytor::new(alg, &buffer).unwrap();
        let plaintext = b"Hello world!";
        let aad = b"";
        let (ciphertext, tag) = enc.encrypt(plaintext, aad).unwrap();
        let decrypted = enc.decrypt(&ciphertext, aad, &tag).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
        let alg = EncryptionAlgorithm::A128CBCHS256;
        let enc_err = ChachaPolyEncrytor::new(alg, &buffer);
        assert!(enc_err.is_err());
    }

    #[test]
    fn test_xchachapoly_encryption() {
        let mut buffer = vec![0u8; 32];
        getrandom::getrandom(&mut buffer).unwrap();
        let alg = EncryptionAlgorithm::XC20P;
        let enc = ChachaPolyEncrytor::new(alg, &buffer).unwrap();
        let plaintext = b"Hello world!";
        let aad = b"";
        let (ciphertext, tag) = enc.encrypt(plaintext, aad).unwrap();
        let decrypted = enc.decrypt(&ciphertext, aad, &tag).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
        let alg = EncryptionAlgorithm::A128CBCHS256;
        let enc_err = ChachaPolyEncrytor::new(alg, &buffer);
        assert!(enc_err.is_err());
    }

    #[test]
    fn test_chachapoly_key_wrap() {
        let mut header = JweHeader::new(JweAlgorithm::C20PKW, EncryptionAlgorithm::None);

        let cek = b"0123456789abcdef";
        let jwk = Jwk::create_oct(b"0123456789abcdef0123456789abcdef").unwrap();
        let wk = ChachaPolyKeyWrap::wrap_key(&mut header, cek, &jwk).unwrap();
        let cek2 = ChachaPolyKeyWrap::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());
    }

    #[test]
    fn test_xchachapoly_key_wrap() {
        let mut header = JweHeader::new(JweAlgorithm::XC20PKW, EncryptionAlgorithm::None);

        let cek = b"0123456789abcdef";
        let jwk = Jwk::create_oct(b"0123456789abcdef0123456789abcdef").unwrap();
        let wk = ChachaPolyKeyWrap::wrap_key(&mut header, cek, &jwk).unwrap();
        let cek2 = ChachaPolyKeyWrap::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());
    }
}
