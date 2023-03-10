//
// Copyright 2023 The Project Oak Authors
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
//

pub mod proto {
    #![allow(clippy::return_self_not_must_use)]
    tonic::include_proto!("oak.session.noninteractive.v1");
}

pub mod transport;
pub mod verifier;

use crate::{
    // verifier::{EvidenceProvider, ReferenceValue, Verifier},
    proto::AttestationEvidence,
};
use anyhow::Context;
use oak_crypto::SenderCryptoProvider;
use oak_remote_attestation_noninteractive::{
    AttestationVerifier, ReferenceValue,
    // AttestationEvidence,
};
use micro_rpc::AsyncTransport;
use std::{vec, vec::Vec};

pub trait EvidenceProvider {
    fn get_evidence(&mut self) -> anyhow::Result<AttestationEvidence>;
}

/// Client for connecting to Oak.
/// Represents a Relying Party from the RATS Architecture:
/// <https://www.rfc-editor.org/rfc/rfc9334.html#name-relying-party>
pub struct OakClient<V: AttestationVerifier> {
    transport: Box<dyn AsyncTransport<Error = anyhow::Error>>,
    verifier: V,
    crypto_provider: SenderCryptoProvider,
}

impl<V: AttestationVerifier> OakClient<V> {
    pub fn create(
        transport: Box<dyn AsyncTransport<Error = anyhow::Error>>,
        mut evidence_provider: Box<dyn EvidenceProvider>,
        reference_value: ReferenceValue,
        // verifier: Box<dyn AttestationVerifier>,
        verifier: V,
    ) -> anyhow::Result<Self> {
        let evidence = evidence_provider
            .get_evidence()
            .context("couldn't get evidence")?;

        verifier
            .verify_attestation(&evidence, &reference_value)
            .context("couldn't verify evidence")?;

        // let encryptor = crypto_provider
        //     .get_encryptor(&evidence.enclave_public_key)
        //     .context("couldn't create encryptor")?;
        let crypto_provider = SenderCryptoProvider::new(&evidence.encryption_public_key);

        Ok(Self {
            transport,
            crypto_provider,
        })
    }

    pub async fn invoke(&mut self, request_body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (encrypted_request, decryptor) = self
            .encryptor
            .encrypt(request_body)
            .context("couldn't encrypt request")?;
        let encrypted_response = self
            .transport
            .invoke(&encrypted_request)
            .context("couldn't send request")?;
        let decrypted_response = decryptor
            .decrypt(&encrypted_response)
            .context("couldn't decrypt response")?;
        Ok(decrypted_response)
    }
}

// // TODO(#3654): Implement client crypto provider.
// pub struct CryptoProvider {}

// impl CryptoProvider {
//     fn get_encryptor(&self, _enclave_public_key: &[u8]) -> anyhow::Result<Encryptor> {
//         Ok(Encryptor {})
//     }
// }

// struct Encryptor {}

// impl Encryptor {
//     /// Returns the encrypted `message` and a corresponding `Decryptor` that should be used
//     /// to decrypt the response message.
//     fn encrypt(&mut self, _message: &[u8]) -> anyhow::Result<(Vec<u8>, Decryptor)> {
//         Ok((vec![], Decryptor {}))
//     }
// }

// struct Decryptor {}

// impl Decryptor {
//     fn decrypt(&self, _encrypted_message: &[u8]) -> anyhow::Result<Vec<u8>> {
//         Ok(vec![])
//     }
// }
