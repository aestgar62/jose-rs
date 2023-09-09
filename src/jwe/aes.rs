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

use super::{wrap::{wrap_cek, unwrap_cek}, RandomGenerator};
use crate::{
    jwe::{JweContent, JweHeader, Jwk},
    utils::{base64_encode_json, generate_hmac, validate_hmac},
    Error,
};

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

use generic_array::{
    typenum::U16,
    ArrayLength,
};

/// Wrap with AES Key Wrap.
/// https://tools.ietf.org/html/rfc5649
#[cfg(feature = "jwe-aes-kw")]
pub fn wrap_aes_kw<T>(key: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error>
where
    T: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    use aes_kw::Kek;
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

/// Encrypt with Aes Cbc mode.
#[cfg(feature = "jwe-aes-cbc")]
fn encrypt_aes_cbc<T>(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error>
where
    T: BlockCipher + BlockEncryptMut + KeyInit + KeySizeUser + BlockSizeUser,
{
    let ciphertext: Vec<u8> =
        cbc::Encryptor::<T>::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok(ciphertext)
}

/// Decrypt with Aes Cbc mode.
#[cfg(feature = "jwe-aes-cbc")]
pub fn decrypt_aes_cbc<T>(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error>
where
    T: BlockCipher + BlockDecryptMut + KeyInit + KeySizeUser + BlockSizeUser,
{
    let plaintext: Vec<u8> = cbc::Decryptor::<T>::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("Aes128Cbc unpad".to_string()))?;
    Ok(plaintext)
}

/// Make AES CBC content.
#[cfg(feature = "jwe-aes-cbc")]
pub fn make_aes_cbc<K: ArrayLength<u8>, I: ArrayLength<u8>>(
    rg: RandomGenerator<K, I>,
    header: &JweHeader,
    jwk: &Jwk,
    content: &[u8],
) -> Result<JweContent, Error> {
    let header_encode = base64_encode_json(&header)?;
    let aad = header_encode.as_bytes();
    let enc_content = match rg.enc_key.len() {
        32 => encrypt_aes_cbc::<Aes128>(content, &rg.enc_key[16..], &rg.iv)?,
        40 => encrypt_aes_cbc::<Aes192>(content, &rg.enc_key[16..], &rg.iv)?,
        48 => encrypt_aes_cbc::<Aes256>(content, &rg.enc_key[16..], &rg.iv)?,
        _ => return Err(Error::InvalidKey("Invalid Key size for AesCBC".to_string())),
    };
    let enc_key = wrap_cek(header, jwk, &rg.enc_key)?;
    let al_bytes = aad_length(aad.len())?;
    let at = [aad, &rg.iv, &enc_content, &al_bytes].concat();
    let mac = generate_hmac(&rg.enc_key[..16], &at)?;
    Ok((header_encode, enc_content, enc_key, rg.iv.to_vec(), mac))
}

/// Extract AES CBC content.
#[cfg(feature = "jwe-aes-cbc")]
pub fn extract_aes_cbc(
    header: &JweHeader,
    jwk: &Jwk,
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Error> {
    let header_encode = base64_encode_json(&header)?;
    let aad = header_encode.as_bytes();
    let enc_key = unwrap_cek(header, jwk, cek)?;
    let al_bytes = aad_length(aad.len())?;
    let at = [aad, iv, ciphertext, &al_bytes].concat();
    validate_hmac(&enc_key[..16], tag, &at)?;

    let plaintext = match enc_key.len() {
        32 => decrypt_aes_cbc::<Aes128>(ciphertext, &enc_key[16..], iv)?,
        40 => decrypt_aes_cbc::<Aes192>(ciphertext, &enc_key[16..], iv)?,
        48 => decrypt_aes_cbc::<Aes256>(ciphertext, &enc_key[16..], iv)?,
        _ => return Err(Error::InvalidKey("Invalid Key size for AesCBC".to_string())),
    };
    Ok(plaintext)
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
    fn test_encrypt_decrypt_aes_cbc() {
        let plaintext = b"Hello world!";
        let iv = b"0123456789abcdef";

        let key = b"0123456789abcdef";
        let ciphertext = encrypt_aes_cbc::<Aes128>(plaintext, key, iv).unwrap();
        let decrypted = decrypt_aes_cbc::<Aes128>(&ciphertext, key, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        let key = b"0123456789abcdef01234567";
        let ciphertext = encrypt_aes_cbc::<Aes192>(plaintext, key, iv).unwrap();
        let decrypted = decrypt_aes_cbc::<Aes192>(&ciphertext, key, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        let key = b"0123456789abcdef0123456789abcdef";
        let ciphertext = encrypt_aes_cbc::<Aes256>(plaintext, key, iv).unwrap();
        let decrypted = decrypt_aes_cbc::<Aes256>(&ciphertext, key, iv).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
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
