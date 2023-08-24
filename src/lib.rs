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

#![allow(clippy::needless_doctest_main)]

//! # jose-rs
//! 
//! Javascript Object Encryption and Signing (JOSE) Library for Rust Language.
//! 
//! ## Supported Algorithms
//! 
//! ### Encryption
//! 
//! - RSA-OAEP
//! - RSA-OAEP-256
//! - RSA1_5
//! - A128CBC-HS256
//! - A192CBC-HS384
//! - A256CBC-HS512
//!     
//! ### Signing
//! 
//! - RS256
//! 