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

#[cfg(feature = "jwe-rsa-kw")]
mod rsa_enc;

#[cfg(feature = "jwe-ecdh-kw")]
mod ecdh;

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::{Jwk, KeyType},
    utils::{base64_decode_json, base64_encode_json},
    Error,
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
    /// The "epk" (ephemeral public key) Header Parameter is used to supply the value to be
    /// used as the ephemeral public key for the agreement algorithm.
    #[serde(rename = "epk", skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<Jwk>,
    /// The "apu" (agreement PartyUInfo) Header Parameter is used to supply the value to be
    /// used as the ephemeral public key identifier for the agreement algorithm.
    #[serde(rename = "apu", skip_serializing_if = "Option::is_none")]
    pub agreement_partyuinfo: Option<String>,
    /// The "apv" (agreement PartyVInfo) Header Parameter is used to supply the value to be
    /// used as the ephemeral public key identifier for the agreement algorithm.
    #[serde(rename = "apv", skip_serializing_if = "Option::is_none")]
    pub agreement_partyvinfo: Option<String>,
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

/// JWE Content Builder.
pub struct JweBuilder {
    /// JWE Header.
    header: JweHeader,
    /// Payload.
    payload: Vec<u8>,
    /// JWE Encrypted Key.
    pub kek: Vec<u8>,
    /// Content Encryption Key.
    pub cek: Vec<u8>,
    /// Initialization Vector.
    pub iv: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
    /// Authentication Tag.
    pub at: Vec<u8>,
}

impl JweBuilder {
    /// Creates a new JWE Content Builder.
    pub fn new(header: &mut JweHeader, payload: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            header: header.clone(),
            payload: payload.to_owned(),
            kek: Vec::new(),
            cek: Vec::new(),
            iv: Vec::new(),
            ciphertext: Vec::new(),
            at: Vec::new(),
        })
    }

    /// From compact JWE.
    pub fn from_compact(jwe: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = jwe.splitn(5, '.').collect();
        let b64_kek = Base64urlUInt::try_from(parts[1].to_owned())
            .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
        let b64_iv = Base64urlUInt::try_from(parts[2].to_owned())
            .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
        let b64_ciphertext = Base64urlUInt::try_from(parts[3].to_owned())
            .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
        let b64_at = Base64urlUInt::try_from(parts[4].to_owned())
            .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
        let header: JweHeader = base64_decode_json(parts[0])?;
        
        Ok(Self {
            header,
            payload: Vec::new(),
            kek: b64_kek.0,
            cek: Vec::new(),
            iv: b64_iv.0,
            ciphertext: b64_ciphertext.0,
            at: b64_at.0,
        })
    }

    /// Build JWE.
    pub fn build(&mut self, jwk: Jwk) -> Result<(), Error> {
        let mut jwk = jwk;
        let alg = &self.header.algorithm;
        if alg.is_key_agreement() {
            let (ss, epk) = ecdh::key_agreement(&jwk)?;
            self.header.ephemeral_public_key = Some(epk);
            let derived_key = ecdh::derive_key(&self.header, &ss)?;
            if alg == &JweAlgorithm::ECDHES {
                self.cek = derived_key;
            } else {
                jwk = Jwk::create_oct(&derived_key)?;
            }
        }
        if !alg.is_direct() {
            let mut buffer = vec![0u8; self.header.encryption.size()];
            getrandom::getrandom(&mut buffer)
                .map_err(|_| Error::Random("getrandom for Encryption Key".to_owned()))?;
            self.cek = buffer;
            self.kek = self.wrap_key(&jwk)?;
        } else {
            if alg == &JweAlgorithm::Dir {
                self.cek = if let KeyType::OCT(key_data) = &jwk.key_type {
                    key_data.key.0.clone()
                } else {
                    return Err(Error::InvalidKey(jwk.key_type.to_string()));
                };
            }
        }
        self.encrypt()
    }

    /// Extract JWE.
    pub fn extract(&mut self, jwk: Jwk) -> Result<(), Error> {
        let mut jwk = jwk;
        let alg = &self.header.algorithm;
        if alg.is_key_agreement() {
            let ss = if let KeyType::OCT(key_data) = &jwk.key_type {
                key_data.key.0.clone()
            } else {
                return Err(Error::InvalidKey(jwk.key_type.to_string()));
            };
            let derived_key = ecdh::derive_key(&self.header, &ss)?;
            if alg == &JweAlgorithm::ECDHES {
                self.cek = derived_key;
            } else {
                jwk = Jwk::create_oct(&derived_key)?;
            }
        }
        if !alg.is_direct() {
            self.cek = self.unwrap_key(&jwk)?;
        } else {
            if alg == &JweAlgorithm::Dir {
                self.cek = if let KeyType::OCT(key_data) = jwk.key_type {
                    key_data.key.0.clone()
                } else {
                    return Err(Error::InvalidKey(jwk.key_type.to_string()));
                };
            }
        }
        self.decrypt()?;
        Ok(())
    }

    /// Build compact JWE.
    pub fn compact_jwe(&self) -> Result<String, Error> {
        let header = self.header.protected()?;
        let b64_jek: Base64urlUInt = Base64urlUInt(self.kek.clone());
        let b64_iv = Base64urlUInt(self.iv.clone());
        let b64_ciphertext = Base64urlUInt(self.ciphertext.clone());
        let b64_at = Base64urlUInt(self.at.clone());
        let compact = format!(
            "{}.{}.{}.{}.{}",
            header, b64_jek, b64_iv, b64_ciphertext, b64_at
        );
        Ok(compact)
    }

    /// Encrypt content.
    pub fn encrypt(&mut self) -> Result<(), Error> {
        let aad = self.header.to_aad()?;
        match self.header.encryption {
            EncryptionAlgorithm::A128CBCHS256
            | EncryptionAlgorithm::A192CBCHS384
            | EncryptionAlgorithm::A256CBCHS512 => {
                let mut buffer = vec![0u8; 16];
                getrandom::getrandom(&mut buffer)
                    .map_err(|_| Error::Random("getrandom for Initialization Vector".to_owned()))?;
                self.iv = buffer;
                let encryptor = aes_cbc::AesCbcEncryptor::from_slice(
                    self.header.encryption,
                    &self.cek,
                    &self.iv,
                )?;
                let (ct, at) = encryptor.encrypt(&self.payload, &aad)?;
                self.ciphertext = ct;
                self.at = at;
                Ok(())
            }
            EncryptionAlgorithm::A128GCM
            | EncryptionAlgorithm::A192GCM
            | EncryptionAlgorithm::A256GCM => {
                let mut buffer = vec![0u8; 12];
                getrandom::getrandom(&mut buffer)
                    .map_err(|_| Error::Random("getrandom for Initialization Vector".to_owned()))?;
                self.iv = buffer;
                let encryptor = aes_gcm::AesGcmEncryptor::from_slice(
                    self.header.encryption,
                    &self.cek,
                    &self.iv,
                )?;
                let (ct, at) = encryptor.encrypt(&self.payload, &aad)?;
                self.ciphertext = ct;
                self.at = at;
                Ok(())
            }
            _ => {
                return Err(Error::UnimplementedAlgorithm(
                    self.header.encryption.to_string(),
                ))
            }
        }
    }

    /// Decrypt content.
    pub fn decrypt(&mut self) -> Result<(), Error> {
        let aad = self.header.to_aad()?;
        match self.header.encryption {
            EncryptionAlgorithm::A128CBCHS256
            | EncryptionAlgorithm::A192CBCHS384
            | EncryptionAlgorithm::A256CBCHS512 => {
                let decryptor = aes_cbc::AesCbcEncryptor::from_slice(
                    self.header.encryption,
                    &self.cek,
                    &self.iv,
                )?;
                let pt = decryptor.decrypt(&self.ciphertext, &aad, &self.at)?;
                self.payload = pt;
                Ok(())
            }   
            EncryptionAlgorithm::A128GCM
            | EncryptionAlgorithm::A192GCM
            | EncryptionAlgorithm::A256GCM => {
                let decryptor = aes_gcm::AesGcmEncryptor::from_slice(
                    self.header.encryption,
                    &self.cek,
                    &self.iv,
                )?;
                let pt = decryptor.decrypt(&self.ciphertext, &aad, &self.at)?;
                self.payload = pt;
                Ok(())
            }
            _ => {
                return Err(Error::UnimplementedAlgorithm(
                    self.header.encryption.to_string(),
                ))
            }
        }
    }

    /// Wrap key.
    fn wrap_key(&mut self, jwk: &Jwk) -> Result<Vec<u8>, Error> {
        match self.header.algorithm {
            #[cfg(feature = "jwe-aes-kw")]
            JweAlgorithm::A128KW
            | JweAlgorithm::A192KW
            | JweAlgorithm::A256KW
            | JweAlgorithm::ECDHESA128KW
            | JweAlgorithm::ECDHESA192KW
            | JweAlgorithm::ECDHESA256KW => Ok(aes_kw::AesKw::wrap_key(
                &mut self.header,
                &self.cek,
                jwk,
            )?),
            #[cfg(feature = "jwe-rsa-kw")]
            JweAlgorithm::RSA1_5 | JweAlgorithm::RSAOAEP | JweAlgorithm::RSAOAEP256 => Ok(
                rsa_enc::RsaEncrypt::wrap_key(&mut self.header, &self.cek, jwk)?,
            ),
            _ => Err(Error::UnimplementedAlgorithm(
                self.header.algorithm.to_string(),
            )),
        }
    }

    /// Unwrap key.
    fn unwrap_key(&mut self, jwk: &Jwk) -> Result<Vec<u8>, Error> {
        match self.header.algorithm {
            #[cfg(feature = "jwe-aes-kw")]
            JweAlgorithm::A128KW
            | JweAlgorithm::A192KW
            | JweAlgorithm::A256KW
            | JweAlgorithm::ECDHESA128KW
            | JweAlgorithm::ECDHESA192KW
            | JweAlgorithm::ECDHESA256KW => Ok(aes_kw::AesKw::unwrap_key(
                &mut self.header,
                &self.kek,
                jwk,
            )?),
            #[cfg(feature = "jwe-rsa-kw")]
            JweAlgorithm::RSA1_5 | JweAlgorithm::RSAOAEP | JweAlgorithm::RSAOAEP256 => Ok(
                rsa_enc::RsaEncrypt::unwrap_key(&mut self.header, &self.kek, jwk)?,
            ),
            _ => Err(Error::UnimplementedAlgorithm(
                self.header.algorithm.to_string(),
            )),
        }
    }
}

/// Encode JWE with default header
pub fn encode_compact_jwe_default(
    alg: JweAlgorithm,
    enc: EncryptionAlgorithm,
    jwk: Jwk,
    payload: &[u8],
) -> Result<String, Error> {
    // create header
    let mut header = JweHeader {
        algorithm: alg,
        encryption: enc,
        ..Default::default()
    };
    encode_compact_jwe(&mut header, jwk, payload)
}

/// Encode compact JWE.
pub fn encode_compact_jwe(header: &mut JweHeader, jwk: Jwk, payload: &[u8]) -> Result<String, Error> {
    let mut builder = JweBuilder::new(header, payload)?;
    builder.build(jwk)?;
    builder.compact_jwe()
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

/// JWE encryptation.
pub trait JweEncryption {

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

/// Key wrapping.
pub trait KeyWrapOrEncrypt {
    /// Wrap or encrypt key.
    ///
    /// # Arguments
    ///
    /// * `header` - JWE Header.
    /// * `cek` - Content Encryption Key.
    /// * `jwk` - JSON Web Key for wrapping or encryption.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Wrapped key.
    ///
    fn wrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error>;

    /// Unwrap or encrypt key.
    ///
    /// # Arguments
    ///
    /// * `header` - JWE Header.
    /// * `cek` - Content Encryption Key.
    /// * `jwk` - JSON Web Key for wrapping or encryption.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - Unwrapped key.
    ///
    fn unwrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error>;
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
    fn test_jwe_builder() {
        let mut header = JweHeader {
            algorithm: JweAlgorithm::RSA1_5,
            encryption: EncryptionAlgorithm::None,
            ..Default::default()
        };
        let jwk = Jwk::create_rsa().unwrap();
        let payload = b"Hello world!";
        test_encrypt_decrypt(&mut header, &jwk, payload);

        header.algorithm = JweAlgorithm::RSAOAEP;
        test_encrypt_decrypt(&mut header, &jwk, payload);

        header.algorithm = JweAlgorithm::RSAOAEP256;
        test_encrypt_decrypt(&mut header, &jwk, payload);

        header.algorithm = JweAlgorithm::A128KW;
        let jwk = Jwk::create_oct(b"0123456789abcdef").unwrap();
        test_encrypt_decrypt(&mut header, &jwk, payload);

        header.algorithm = JweAlgorithm::A192KW;
        let jwk = Jwk::create_oct(b"0123456789abcdef01234567").unwrap();
        test_encrypt_decrypt(&mut header, &jwk, payload);

        header.algorithm = JweAlgorithm::A256KW;
        let jwk = Jwk::create_oct(b"0123456789abcdef0123456789abcdef").unwrap();
        test_encrypt_decrypt(&mut header, &jwk, payload);

    }

    fn test_encrypt_decrypt(header: &mut JweHeader, jwk: &Jwk, payload: &[u8]) {
        for value in EncryptionAlgorithm::VALUES {
            header.encryption = value;
            let mut builder = JweBuilder::new(header, payload).unwrap();
            builder.build(jwk.clone()).unwrap();
            let compact = builder.compact_jwe().unwrap();
            let mut jwe = JweBuilder::from_compact(&compact).unwrap();
            jwe.extract(jwk.clone()).unwrap();
            assert_eq!(jwe.payload, payload);
        }
    }

    #[test]
    fn test_direct_mode() {
        let mut header = JweHeader {
            algorithm: JweAlgorithm::Dir,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        let payload = b"Hello world!";

        for value in EncryptionAlgorithm::VALUES {
            header.encryption = value;
            let bytes = vec![0x0u8; value.size()];
            let jwk = Jwk::create_oct(&bytes).unwrap();
            let mut builder = JweBuilder::new(&mut header, payload).unwrap();
            builder.build(jwk.clone()).unwrap();
            let compact = builder.compact_jwe().unwrap();
            let mut jwe = JweBuilder::from_compact(&compact).unwrap();
            jwe.extract(jwk).unwrap();
            assert_eq!(jwe.payload, payload);
        }
    }

    #[test]
    fn test_key_agreement() {
        let mut header = JweHeader {
            algorithm: JweAlgorithm::ECDHES,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        let payload = b"Hello world!";
        test_build_extract_key_agreement(&mut header, payload);

        header.algorithm = JweAlgorithm::ECDHESA128KW;
        test_build_extract_key_agreement(&mut header, payload);

        header.algorithm = JweAlgorithm::ECDHESA192KW;
        test_build_extract_key_agreement(&mut header, payload);

        header.algorithm = JweAlgorithm::ECDHESA256KW;
        test_build_extract_key_agreement(&mut header, payload);
    }

    fn test_build_extract_key_agreement(header: &mut JweHeader, payload: &[u8]) {
        use k256::{PublicKey, ecdh::EphemeralSecret};
        use rand_core::OsRng;

        for value in EncryptionAlgorithm::VALUES {
            header.encryption = value;
            let esk = EphemeralSecret::random(&mut OsRng);
            let jwk = Jwk::try_from(&esk.public_key()).unwrap();
            let mut builder = JweBuilder::new(header, payload).unwrap();
            builder.build(jwk.clone()).unwrap();
            let compact = builder.compact_jwe().unwrap();

            let mut jwe = JweBuilder::from_compact(&compact).unwrap();
            let epk = jwe.header.ephemeral_public_key.clone().unwrap();
            let pk = PublicKey::try_from(&epk).unwrap();
            let ss = esk.diffie_hellman(&pk);
            let jwk = Jwk::create_oct(ss.raw_secret_bytes()).unwrap();
            jwe.extract(jwk).unwrap();

            assert_eq!(jwe.payload, payload);
        }
    }
}
