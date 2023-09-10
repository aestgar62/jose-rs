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

//! # Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC) Mode
//!

#![deny(missing_docs)]

use super::{
    wrap::{unwrap_cek, wrap_cek},
    JweContent, JweEncrypter, JweHeader, JweJson, RandomGenerator, KeyWrapper,
};

use crate::{
    jwk::{Jwk, KeyType},
    utils::{base64_encode_json, generate_hmac, validate_hmac},
    Error, jwa::{EncryptionAlgorithm, JweAlgorithm},
};

#[cfg(feature = "jwe-aes")]
use aes::{
    cipher::{
        block_padding::Pkcs7, BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt,
        BlockEncryptMut, BlockSizeUser, KeyIvInit, KeySizeUser,
    },
    Aes128, Aes192, Aes256,
};

#[cfg(feature = "jwe-aes-gcm")]
use aes_gcm::{Key, Nonce};

#[cfg(feature = "jwe-aes-gcm")]
use aead::{Aead, KeyInit};

#[cfg(feature = "jwe-aes-kw")]
use aes_kw::Kek;

use generic_array::{typenum::U16, ArrayLength};

/// AesCbc encrypter.
#[cfg(feature = "jwe-aes-cbc")]
#[derive(Debug)]
pub struct AesCbcEncrypter;

#[cfg(feature = "jwe-aes-cbc")]
impl JweEncrypter for AesCbcEncrypter {
    fn encrypt<K: ArrayLength<u8>, I: ArrayLength<u8>>(
        rg: &RandomGenerator<K, I>,
        header: &JweHeader,
        jwk: &Jwk,
        content: &[u8],
    ) -> Result<JweJson, Error> {
        let key_len = rg.enc_key.len() / 2;
        let (cek, iv) = rg.enc_key.split_at(key_len);
        let ciphertext = Self::encrypt_content(header, cek, iv, content)?;
        //let ciphertext = Self::encrypt_content(header, cek, iv, content)
        unimplemented!("AesCbcEncrypter")
    }

    fn encrypt_compact<K, I>(
        rg: &RandomGenerator<K, I>,
        header: &JweHeader,
        jwk: &Jwk,
        content: &[u8],
    ) -> Result<String, Error>
    where
        K: ArrayLength<u8>,
        I: ArrayLength<u8>,
    {
        unimplemented!("AesCbcEncrypter")
    }

    fn encrypt_content(
        header: &JweHeader,
        cek: &[u8],
        iv: &[u8],
        content: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ciphertext = match header.encryption {
            EncryptionAlgorithm::A128CBCHS256 => {
                cbc::Encryptor::<aes::Aes128>
                    ::new(cek.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(content)
            },
            EncryptionAlgorithm::A192CBCHS384 => {
                cbc::Encryptor::<aes::Aes192>
                    ::new(cek.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(content)
            },
            EncryptionAlgorithm::A256CBCHS512 => {
                cbc::Encryptor::<aes::Aes256>
                    ::new(cek.into(), iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(content)
            },
            _ => return Err(Error::InvalidAlgorithm(header.encryption.to_string())),
        };
        Ok(ciphertext)
    }


}

/// AES Key Wrapper.
/// https://tools.ietf.org/html/rfc3394
/// 
#[cfg(feature = "jwe-aes-kw")]
pub struct AesKw;

#[cfg(feature = "jwe-aes-kw")]
impl KeyWrapper for AesKw {
    fn wrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let wk = match alg {
            JweAlgorithm::A128KW => {
                let wrapper = Kek::<Aes128>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
                wrapper.wrap_vec(cek).map_err(|_| {
                    Error::Encrypt("AESKW wrap".to_string())
                })?
            },
            JweAlgorithm::A192KW => {
                let wrapper = Kek::<Aes192>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
                wrapper.wrap_vec(cek).map_err(|_| {
                    Error::Encrypt("AESKW wrap".to_string())
                })?
            },
            JweAlgorithm::A256KW => {
                let wrapper = Kek::<Aes256>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
                wrapper.wrap_vec(cek).map_err(|_| {
                    Error::Encrypt("AESKW wrap".to_string())
                })?
            },
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };
        Ok(wk)
    }

    fn unwrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let cek = match alg {
            JweAlgorithm::A128KW => {
                let wrapper = Kek::<Aes128>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
                wrapper.unwrap_vec(cek).map_err(|_| {
                    Error::Decrypt("AESKW unwrap".to_string())
                })?
            },
            JweAlgorithm::A192KW => {
                let wrapper = Kek::<Aes192>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
                wrapper.unwrap_vec(cek).map_err(|_| {
                    Error::Decrypt("AESKW unwrap".to_string())
                })?
            },
            JweAlgorithm::A256KW => {
                let wrapper = Kek::<Aes256>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
                wrapper.unwrap_vec(cek).map_err(|_| {
                    Error::Decrypt("AESKW unwrap".to_string())
                })?        
            },
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };  
        Ok(cek)
    }
    
}

/// Wrap with AES Key Wrap.
/// https://tools.ietf.org/html/rfc5649
#[cfg(feature = "jwe-aes-kw")]
pub fn wrap_aes_kw<T>(key: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error>
where
    T: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    let kek = Kek::<T>::new(kw.into());
    Ok(kek
        .wrap_vec(key)
        .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?)
}

/// Unwrap with AES Key Wrap.
/// https://tools.ietf.org/html/rfc5649
#[cfg(feature = "jwe-aes-kw")]
pub fn unwrap_aes_kw<T>(cipherkey: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error>
where
    T: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    use aes_kw::Kek;
    let kek = Kek::<T>::new(kw.into());
    Ok(kek
        .unwrap_vec(cipherkey)
        .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?)
}

/// Encrypt with AES-GCM algorithm.
/// https://tools.ietf.org/html/rfc7518#section-5.3
#[cfg(feature = "jwe-aes-gcm")]
pub fn encrypt_aes_gcm<T>(
    plaintext: &[u8],
    key: &[u8],
    aad: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Error>
where
    T: Aead + KeyInit,
{
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let key = Key::<T>::from_slice(key);
    let cipher = T::new(key);
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| Error::Encrypt("A128GMC".to_owned()))?;
    Ok(ciphertext)
}

/// Decrypt with AES-GCM algorithm.
/// https://tools.ietf.org/html/rfc7518#section-5.3
#[cfg(feature = "jwe-aes-gcm")]
pub fn decrypt_aes_gcm<T>(
    ciphertext: &[u8],
    key: &[u8],
    aad: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Error>
where
    T: Aead + KeyInit,
{
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let key = Key::<T>::from_slice(key);
    let cipher = T::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| Error::Decrypt("A128GMC".to_owned()))?;
    Ok(plaintext)
}

/// Make AES GCM content.
/// https://tools.ietf.org/html/rfc7518#section-5.3
#[cfg(feature = "jwe-aes-gcm")]
pub fn make_aes_gcm<K: ArrayLength<u8>, I: ArrayLength<u8>>(
    rg: &RandomGenerator<K, I>,
    header: &JweHeader,
    jwk: Jwk,
    content: &[u8],
) -> Result<JweContent, Error> {
    let header_encode = base64_encode_json(&header)?;
    let aad = header_encode.as_bytes();

    //let enc_content = encrypt_aes_gcm::<AesGcm<Aes128, U12>>(content, key, aad, nonce)?;
    //let enc_key = wrap_cek(header, &Jwk::new_oct(key.to_vec()), key)?;
    //Ok((enc_content, enc_key, iv.to_vec(), vec![]))
    unimplemented!()
}

/// Calculates authenticated length.
#[cfg(feature = "jwe-aes-cbc")]
fn aad_length(hsize: usize) -> Result<[u8; 8], Error> {
    let al: u64 = hsize as u64 * 8;
    Ok(al.to_be_bytes())
}

#[cfg(test)]
mod tests {

    use super::*;
    use ::aes_gcm::AesGcm;

    #[test]
    fn test_wrap_unwrap_aes_kw() {
        let key = b"0123456789abcdef0123456789abcdef";

        let kw = b"0123456789abcdef";
        let cipherkey = wrap_aes_kw::<Aes128>(key, kw).unwrap();
        let decrypted = unwrap_aes_kw::<Aes128>(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());

        let kw = b"0123456789abcdef01234567";
        let cipherkey = wrap_aes_kw::<Aes192>(key, kw).unwrap();
        let decrypted = unwrap_aes_kw::<Aes192>(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());

        let kw = b"0123456789abcdef0123456789abcdef";
        let cipherkey = wrap_aes_kw::<Aes256>(key, kw).unwrap();
        let decrypted = unwrap_aes_kw::<Aes256>(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());
    }

    #[test]
    #[cfg(feature = "jwe-aes-gcm")]
    fn test_encrypt_decrypt_aes_gcm() {
        use aes_gcm::{Aes128Gcm, Aes256Gcm};
        use generic_array::typenum::U12;
        type Aes192Gcm = AesGcm<Aes192, U12>;

        let plaintext = b"Hello world!";
        let iv = b"0123456789ab";
        let aad = b"hello...";

        let key = b"0123456789abcdef";
        let ciphertext = encrypt_aes_gcm::<Aes128Gcm>(plaintext, key, aad, iv).unwrap();
        let decrypted = decrypt_aes_gcm::<Aes128Gcm>(&ciphertext, key, aad, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        let key = b"0123456789abcdef01234567";
        let ciphertext = encrypt_aes_gcm::<Aes192Gcm>(plaintext, key, aad, iv).unwrap();
        let decrypted = decrypt_aes_gcm::<Aes192Gcm>(&ciphertext, key, aad, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        let key = b"0123456789abcdef0123456789abcdef";
        let ciphertext = encrypt_aes_gcm::<Aes256Gcm>(plaintext, key, aad, iv).unwrap();
        let decrypted = decrypt_aes_gcm::<Aes256Gcm>(&ciphertext, key, aad, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
