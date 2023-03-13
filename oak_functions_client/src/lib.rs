//
// Copyright 2021 The Project Oak Authors
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

pub mod rekor;

use anyhow::Context;
use oak_client::{
    OakClient,
    transport::GrpcStreamingTransport,
    proto::streaming_session_client::StreamingSessionClient,
};
use oak_remote_attestation_noninteractive::{
    EmptyAttestationVerifier, ReferenceValue,
};
use tonic::transport::Channel;

#[cfg(test)]
mod tests;

pub struct OakFunctionsClient {
    oak_client: oak_client::OakClient<GrpcStreamingTransport, EmptyAttestationVerifier>,
}

impl OakFunctionsClient {
    pub async fn new(uri: &str) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(uri.to_string())
            .context("couldn't create gRPC channel")?
            .connect()
            .await?;
        let transport = GrpcStreamingTransport::new(StreamingSessionClient::new(channel));
        let oak_client = OakClient::create(
            transport,
            EmptyAttestationVerifier,
            ReferenceValue { binary_hash: vec![] }
        )
        .await
        .context("couldn't create Oak client")?;
        Ok(Self { oak_client })
    }

    pub async fn invoke(&mut self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let response = self
            .oak_client
            .invoke(request)
            .await
            .context("couldn't invoke Oak Functions instance")?;
        Ok(response)
    }
}
