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

//! # JSON Web Encryption (JWE)
//!
//! JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
//!

#![deny(missing_docs)]

#[cfg(feature = "jwe-aes-kw")]
mod aes_kw;

#[cfg(feature = "jwe-aes-cbc")]
mod aes_cbc;

#[cfg(feature = "jwe-aes-gcm")]
mod aes_gcm;

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::Jwk,
    utils::{base64_decode_json, base64_encode_json},
    Error,
};

use generic_array::{
    ArrayLength, GenericArray,
};
use ptypes::{Base64urlUInt, Uri};

use serde::{Deserialize, Serialize};

/// For JWE, describe the encryption applied to the plaintext and optionally additional properties
/// of the JWE.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    /// The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to
    /// encrypt or determine the value of the Content Encryption Key (CEK).
    #[serde(rename = "alg")]
    pub algorithm: JweAlgorithm,
    /// The "enc" (encryption algorithm) Header Parameter identifies the content encryption algorithm
    /// used to perform authenticated encryption on the plaintext to produce the ciphertext and the
    /// Authentication Tag.
    #[serde(rename = "enc")]
    pub encryption: EncryptionAlgorithm,
    /// The "zip" (compression algorithm) Header Parameter indicates whether the plaintext
    /// has been compressed before encryption.
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    /// The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of
    /// JSON-encoded public keys, one of which corresponds to the key used to encrypt the JWE.
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwk_set_url: Option<Uri>,
    /// The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key
    /// used to encrypt the JWE.
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the
    /// JWE.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The "x5u" (X.509 URL) Header Parameter is a URI that refers to a resource for the X.509
    /// public key certificate or certificate chain corresponding to the key used to encrypt the
    /// JWE.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<Uri>,
    /// The "x5c" (X.509 Certificate Chain) Header Parameter contains the X.509 public key  
    /// certificate or certificate chain corresponding to the key used to encrypt the JWE.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,
    /// The "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter is a base64url-encoded
    /// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_sha1_thumbprint: Option<String>,
    /// The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter is a base64url-
    /// encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_sha256_thumbprint: Option<String>,
    /// The "typ" (type) Header Parameter is used by JWE applications to declare the media type
    /// [IANA.MediaTypes] of this complete JWE.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// The "cty" (content type) Header Parameter is used by JWE applications to declare the media
    /// type [IANA.MediaTypes] of the secured content (the plaintext) or to declare nested
    /// JWE objects.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// The "crit" (critical) Header Parameter indicates that extensions to this specification
    /// and/or [JWA] are being used that MUST be understood and processed.
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

impl JweHeader {
    /// Creates a new JWE Header.
    ///
    /// # Arguments
    ///
    /// * `alg` - JWE Algorithm.
    /// * `enc` - Encryption Algorithm.
    ///
    /// # Returns
    ///
    /// * `Self` - JWE Header.
    ///
    pub fn new(alg: JweAlgorithm, enc: EncryptionAlgorithm) -> Self {
        Self {
            algorithm: alg,
            encryption: enc,
            ..Default::default()
        }
    }

    /// Gets Additional Authenticated Data from JWE Header.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Additional Authenticated Data.
    ///
    pub fn to_aad(&self) -> Result<Vec<u8>, Error> {
        let header_bytes = base64_encode_json(self)?;
        Ok(header_bytes.as_bytes().to_vec())
    }

    /// Gets protected header.
    ///
    /// # Returns
    ///
    /// * `Result<String, Error>` - Protected header.
    ///
    pub fn protected(&self) -> Result<String, Error> {
        base64_encode_json(self)
    }
}

/// JWE Content.
pub type JweContent = (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Encode JWE with default header
pub fn encode_compact_jwe_default(
    alg: JweAlgorithm,
    enc: EncryptionAlgorithm,
    jwk: &Jwk,
    payload: &[u8],
) -> Result<String, Error> {
    // create header
    let header = JweHeader {
        algorithm: alg,
        encryption: enc,
        ..Default::default()
    };

    encode_compact_jwe(&header, jwk, payload)
}

/// Encode compact JWE content
pub fn encode_compact_jwe(header: &JweHeader, jwk: &Jwk, payload: &[u8]) -> Result<String, Error> {
    let jwe_content = make_jwe_content(header, jwk, payload)?;
    let b64_cek: Base64urlUInt = Base64urlUInt(jwe_content.1);
    let b64_iv = Base64urlUInt(jwe_content.2);
    let b64_ciphertext = Base64urlUInt(jwe_content.3);
    let b64_at = Base64urlUInt(jwe_content.4);
    let compact = format!(
        "{}.{}.{}.{}.{}",
        jwe_content.0, b64_cek, b64_iv, b64_ciphertext, b64_at
    );
    Ok(compact)
}

/// Decode compact JWE.
pub fn decode_compact_jwe(jwk: Jwk, jwe: &str) -> Result<Vec<u8>, Error> {
    let parts: Vec<&str> = jwe.splitn(5, '.').collect();
    let b64_cek = Base64urlUInt::try_from(parts[1].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_iv = Base64urlUInt::try_from(parts[2].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_ciphertext = Base64urlUInt::try_from(parts[3].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_at = Base64urlUInt::try_from(parts[4].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;

    extract_jwe_content(jwk, (
        parts[0].to_owned(),
        b64_cek.0,
        b64_iv.0,
        b64_ciphertext.0,
        b64_at.0,
    ))
}

/// Make JWE Content.
fn make_jwe_content(header: &JweHeader, jwk: &Jwk, payload: &[u8]) -> Result<JweContent, Error> {
    match header.encryption {
        EncryptionAlgorithm::A128CBCHS256
        | EncryptionAlgorithm::A192CBCHS384
        | EncryptionAlgorithm::A256CBCHS512 => {
            let encryptor = aes_cbc::AesCbcEncryptor::from_random(header.encryption)?;
            let aad = header.to_aad()?;
            let (ct, at) = encryptor.encrypt(payload, &aad)?;
            let wk = wrap_key(header.algorithm, &encryptor.key, jwk)?;
            Ok((header.protected()?, wk, encryptor.iv.clone(), ct, at))
        }
        EncryptionAlgorithm::A128GCM
        | EncryptionAlgorithm::A192GCM
        | EncryptionAlgorithm::A256GCM => {
            let encryptor = aes_gcm::AesGcmEncryptor::from_random(header.encryption)?;
            let aad = header.to_aad()?;
            let (ct, at) = encryptor.encrypt(payload, &aad)?;
            let wk = wrap_key(header.algorithm, &encryptor.key, jwk)?;
            Ok((header.protected()?, wk, encryptor.iv.clone(), ct, at))
        }
        _ => Err(Error::UnimplementedAlgorithm(header.encryption.to_string())),
    }
}

/// Extract JWE Content.
fn extract_jwe_content(
    jwk: Jwk,
    content: JweContent,
) -> Result<Vec<u8>, Error> {
    let header: JweHeader = base64_decode_json(&content.0)?;
    match header.encryption {
        EncryptionAlgorithm::A128CBCHS256 |
        EncryptionAlgorithm::A192CBCHS384 |
        EncryptionAlgorithm::A256CBCHS512 => {
            let wk = unwrap_key(header.algorithm, &content.1, &jwk)?;
            let decryptor = aes_cbc::AesCbcEncryptor::from_slice(header.encryption, &wk, &content.2)?;
            let aad = header.to_aad()?;
            decryptor.decrypt(&content.3, &aad, &content.4)
        },
        EncryptionAlgorithm::A128GCM |
        EncryptionAlgorithm::A192GCM |
        EncryptionAlgorithm::A256GCM => {
            let wk = unwrap_key(header.algorithm, &content.1, &jwk)?;
            let decryptor = aes_gcm::AesGcmEncryptor::from_slice(header.encryption, &wk, &content.2)?;
            let aad = header.to_aad()?;
            decryptor.decrypt(&content.3, &aad, &content.4)
        },
        _ => Err(Error::UnimplementedAlgorithm(header.encryption.to_string())),
    }
}

/// JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweJson {
    /// The "protected" member contains the JWE Protected Header.
    #[serde(rename = "protected")]
    pub protected: String,
    /// The "unprotected" member contains the JWE Unprotected Header.
    #[serde(rename = "unprotected", skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<JweHeader>,
    /// The "recipients" member contains an array of JWE Encrypted Key values.
    #[serde(rename = "recipients")]
    pub recipients: Vec<JweRecipient>,
    /// The "aad" member contains the Additional Authenticated Data.
    #[serde(rename = "aad", skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
    /// The "iv" member contains the Initialization Vector.
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    /// The "ciphertext" member contains the Ciphertext.
    #[serde(rename = "ciphertext", skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// The "tag" member contains the Authentication Tag.
    #[serde(rename = "tag", skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// The "recipients" member contains an array of JWE Encrypted Key values.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweRecipient {
    /// The "header" member contains the per-Recipient Header.
    #[serde(rename = "header", skip_serializing_if = "Option::is_none")]
    pub header: Option<JweHeader>,
    /// The "encrypted_key" member contains the Encrypted Key value.
    #[serde(rename = "encrypted_key", skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<String>,
}

/// Wrap key.
fn wrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
    match alg {
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            Ok(aes_kw::AesKw::wrap_key(alg, cek, jwk)?)
        }
        _ => Err(Error::UnimplementedAlgorithm(alg.to_string())),
    }
}

/// Unwrap key.
fn unwrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
    match alg {
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW | JweAlgorithm::A192KW | JweAlgorithm::A256KW => {
            Ok(aes_kw::AesKw::unwrap_key(alg, cek, jwk)?)
        }
        _ => Err(Error::UnimplementedAlgorithm(alg.to_string())),
    }
}

/// Random Generator
#[derive(Default, Debug)]
pub struct RandomGenerator<K: ArrayLength<u8>, I: ArrayLength<u8>> {
    /// Encription Key array
    pub enc_key: GenericArray<u8, K>,
    /// Initilization vector array
    pub iv: GenericArray<u8, I>,
}

impl<K: ArrayLength<u8>, I: ArrayLength<u8>> RandomGenerator<K, I> {
    /// Create new Random Generator and generate random values.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - Random Generator.
    ///
    pub fn generate() -> Result<Self, Error> {
        let mut rg = Self::default();
        getrandom::getrandom(&mut rg.enc_key)
            .map_err(|_| Error::Random("getrandom for Encryption Key".to_owned()))?;
        getrandom::getrandom(&mut rg.iv)
            .map_err(|_| Error::Random("getrandom for Initialization Vector".to_owned()))?;
        Ok(rg)
    }
}

/// JWE encryptation.
pub trait JweEncryption {
    /// Creates from random generator.
    ///
    /// # Arguments
    ///
    /// * `alg` - Encryption Algorithm.
    ///
    /// # Returns
    ///
    /// * `Self` - JWE Encryption.
    ///
    fn from_random(alg: EncryptionAlgorithm) -> Result<Self, Error>
    where
        Self: Sized;

    /// Create from slice.
    ///
    /// # Arguments
    ///
    /// * `alg` - Encryption Algorithm.
    /// * `cek` - Content Encryption Key.
    /// * `iv` - Initialization Vector.
    ///
    /// # Returns
    ///
    /// * `Self` - JWE Encryption.
    ///
    fn from_slice(alg: EncryptionAlgorithm, cek: &[u8], iv: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encrypt content with authentication.
    ///
    /// # Arguments
    ///
    /// * `content` - Content to encrypt.
    /// * `aad` - Additional Authenticated Data.
    ///
    /// # Returns
    ///
    /// * `Result<(Vec<u8>, Vec<u8>), Error>` - Encrypted content and authentication tag.
    ///
    fn encrypt(&self, content: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Decrypt content with authentication.
    ///
    /// # Arguments
    ///  
    /// * `content` - Content to decrypt.
    /// * `aad` - Additional Authenticated Data.
    /// * `at` - Authentication Tag.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Decrypted content.
    ///
    fn decrypt(&self, content: &[u8], aad: &[u8], at: &[u8]) -> Result<Vec<u8>, Error>;
}

/// JWE decrypter.
pub trait JweDecrypter {
    /// Decrypt content.
    ///
    /// # Arguments
    ///
    /// * `jwk` - JSON Web Key.
    /// * `jwe` - JWE content.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Decrypted content.
    ///
    fn decrypt(jwk: &Jwk, jwe: &JweJson) -> Result<Vec<u8>, Error>;

    /// Decrypt content from compact JWE.
    ///
    /// # Arguments
    ///
    /// * `jwk` - JSON Web Key.
    /// * `jwe` - Compact JWE.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Decrypted content.
    ///
    fn decrypt_compact(jwk: &Jwk, jwe: &str) -> Result<Vec<u8>, Error>;
}

/// Key wrapping.
pub trait KeyWrapper {
    /// Wrap key.
    ///
    /// # Arguments
    ///
    /// * `cek` - Content Encryption Key.
    /// * `jwk` - JSON Web Key.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Wrapped key.
    ///
    fn wrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error>;

    /// Unwrap key.
    ///
    /// # Arguments
    ///
    /// * `cek` - Content Encryption Key.
    /// * `jwk` - JSON Web Key.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Unwrapped key.
    ///
    fn unwrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error>;
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::base64_encode_json;

    #[test]
    fn test_jwe_header_default() {
        let header = JweHeader::default();
        assert_eq!(header.algorithm, JweAlgorithm::None);
        assert_eq!(header.encryption, EncryptionAlgorithm::None);
    }

    #[test]
    fn test_jwe_protected_header() {
        let protected = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".to_owned();
        let header = JweHeader {
            algorithm: JweAlgorithm::RSA1_5,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        assert_eq!(header.algorithm, JweAlgorithm::RSA1_5);
        assert_eq!(header.encryption, EncryptionAlgorithm::A128CBCHS256);
        let result = base64_encode_json(&header).unwrap();
        assert_eq!(result, protected);
    }

    #[test]
    fn test_random_generation() {
        use generic_array::typenum::{U16, U32};

        let generator = RandomGenerator::<U32, U16>::generate().unwrap();
        assert_eq!(generator.enc_key.len(), 32);
        assert_eq!(generator.iv.len(), 16);
    }

    #[test]
    fn test_jwe_content() {
        let header = JweHeader {
            algorithm: JweAlgorithm::A128KW,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        let jwk = Jwk::create_oct(b"0123456789abcdef").unwrap();

        let payload = b"Hello world!";
        let content = encode_compact_jwe(&header, &jwk, payload).unwrap();
        let payload2 = decode_compact_jwe(jwk, &content).unwrap();
        assert_eq!(payload, payload2.as_slice());

    }
}
