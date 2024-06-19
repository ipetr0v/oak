//
// Copyright 2024 The Project Oak Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Simple CLI that verifies the provided measurements against evidences and endorsements.

use std::{fs, path::PathBuf};

use clap::Parser;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;

#[derive(Parser, Clone, Debug, PartialEq)]
pub struct Params {
    /// Input claim path.
    #[arg(long, value_parser = path_exists)]
    pub claim: PathBuf,

    /// Output claim signature path.
    #[arg(long, value_parser = path_exists)]
    pub claim_signature: PathBuf,
}

pub fn path_exists(s: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(s);
    if !fs::metadata(s).map_err(|err| err.to_string())?.is_file() {
        Err(String::from("path does not represent a file"))
    } else {
        Ok(path)
    }
}

fn main() {
    let Params {
        claim,
        claim_signature,
    } = Params::parse();

    let claim = fs::read(claim).expect("couldn't open claim");

    let signing_key = SigningKey::random(&mut OsRng);
    let signature = <p256::ecdsa::SigningKey as p256::ecdsa::signature::Signer<
    p256::ecdsa::Signature,
>>::sign(&signing_key, &claim);

    fs::write(claim_signature, signature.to_vec())
        .expect("couldn't write claim signature");
}
