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

use std::{fs, path::PathBuf, process::Command};

use clap::Parser;
use oak_attestation_verification::verifier::{to_attestation_results, verify};
use oak_crypto::verifier::{Verifier, VerifierKeyHandle};
use oak_proto_rust::oak::{
    attestation::v1::{
        attestation_results::Status, binary_reference_value, reference_values,
        AmdSevReferenceValues, SystemLayerReferenceValues, BinaryReferenceValue, Digests,
        Endorsements, Evidence, KernelLayerReferenceValues, OakContainersReferenceValues,
        ReferenceValues, RootLayerReferenceValues, SkipVerification, ContainerLayerReferenceValues,
        KernelBinaryReferenceValue, TextReferenceValue, text_reference_value,
        kernel_binary_reference_value, KernelDigests, RegexReferenceValue,
        regex_reference_value,
    },
    crypto::v1::Signature,
    RawDigest,
};
use p256::ecdsa::VerifyingKey;
use prost::Message;

// Timestamp taken for the purpose of demo: 5 Mar 2024, 12:27 UTC.
const NOW_UTC_MILLIS: i64 = 1709641620000;

#[derive(Parser, Clone, Debug, PartialEq)]
pub struct Params {
    /// Path to the evidence to verify.
    #[arg(long, value_parser = path_exists)]
    pub evidence: PathBuf,

    /// Path endorsements.
    #[arg(long, value_parser = path_exists)]
    pub endorsements: PathBuf,

    /// Expected Sha2-384 hash of the initial measurement of the VM memory in the attestation
    /// report.
    #[arg(
        long,
        value_parser = parse_hex_sha2_384_hash,
        default_value = "sha2-384:865a42c8ed9b84f968c00c5b8a05f5f75180275d9d7d531a4af004617f668b50a508f46ad1b77163b0d52cbb74299352",
    )]
    pub initial_measurement: BinaryReferenceValue,

    /// Expected Sha2-256 hash of the Kernel Image.
    #[arg(
        long,
        value_parser = parse_kernel_hex_sha2_256_hash,
        default_value = "sha2-256:17c664e5535268a0f8680ffe851418d57e0304a0a52ec97c52e59469ac3a4ae1",
    )]
    pub kernel_image_measurement: RawDigest,

    /// Expected Sha2-256 hash of the Kernel Setup Data.
    #[arg(
        long,
        value_parser = parse_kernel_hex_sha2_256_hash,
        default_value = "sha2-256:8560e0be8f755eeab42fea601f766b3f3e543b697ce0a732212d9ae2559ac093",
    )]
    pub kernel_setup_data_measurement: RawDigest,

    /// Expected Sha2-256 hash of the setup data for the System Image.
    #[arg(
            long,
            value_parser = parse_hex_sha2_256_hash,
            default_value = "sha2-256:83d0ab9f34938c30a4c94a9fc21fb459315bc415238c8ab9083a4a53cbb05dc9",
        )]
    pub system_image_measurement: BinaryReferenceValue,

    /// Expected Sha2-256 hash of the Enclave Application.
    #[arg(
        long,
        value_parser = parse_hex_sha2_256_hash,
        default_value = "sha2-256:00cc84ed68ce34e869d95f93f4788dfbd6a58dd511a71378caa30327bc37b8f8",
    )]
    pub application_measurement: BinaryReferenceValue,

    /// Claim path.
    #[arg(long, value_parser = path_exists)]
    pub claim: PathBuf,

    /// Claim signature path.
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

pub fn parse_hex_sha2_256_hash(hex_sha2_256_hash: &str) -> Result<BinaryReferenceValue, String> {
    let hash = {
        let parts: Vec<&str> = hex_sha2_256_hash.split(':').collect();
        if parts[0] != "sha2-256" || parts.len() != 2 {
            println!("Invalid input format");
            return Err("invalid hash".to_string());
        }
        parts[1]
    };
    let raw_digest = RawDigest {
        sha2_256: hex::decode(hash).map_err(|_| "failed to parse hash".to_string())?,
        ..Default::default()
    };
    let digests = [raw_digest].to_vec();
    Ok(BinaryReferenceValue {
        r#type: Some(binary_reference_value::Type::Digests(Digests { digests })),
    })
}

pub fn parse_kernel_hex_sha2_256_hash(hex_sha2_256_hash: &str) -> Result<RawDigest, String> {
    let hash = {
        let parts: Vec<&str> = hex_sha2_256_hash.split(':').collect();
        if parts[0] != "sha2-256" || parts.len() != 2 {
            println!("Invalid input format");
            return Err("invalid hash".to_string());
        }
        parts[1]
    };
    let raw_digest = RawDigest {
        sha2_256: hex::decode(hash).map_err(|_| "failed to parse hash".to_string())?,
        ..Default::default()
    };
    Ok(raw_digest)
    // let digests = [raw_digest].to_vec();
    // Ok(KernelBinaryReferenceValue {
    //     r#type: Some(kernel_binary_reference_value::Type::Digests(KernelDigests {
    //         image: Some(Digests { digests }),
    //         // setup_data: Some(Digests { digests: vec![] }),
    //         setup_data: None,
    //     })),
    // })
}

pub fn parse_hex_sha2_384_hash(hex_sha2_384_hash: &str) -> Result<BinaryReferenceValue, String> {
    let hash = {
        let parts: Vec<&str> = hex_sha2_384_hash.split(':').collect();
        if parts[0] != "sha2-384" || parts.len() != 2 {
            println!("Invalid input format");
            return Err("invalid hash".to_string());
        }
        parts[1]
    };
    let raw_digest = RawDigest {
        sha2_384: hex::decode(hash).map_err(|_| "failed to parse hash".to_string())?,
        ..Default::default()
    };
    let digests = [raw_digest].to_vec();
    Ok(BinaryReferenceValue {
        r#type: Some(binary_reference_value::Type::Digests(Digests { digests })),
    })
}

fn main() {
    let Params {
        evidence,
        endorsements,
        initial_measurement,
        kernel_image_measurement,
        kernel_setup_data_measurement,
        system_image_measurement,
        application_measurement,
        claim,
        claim_signature,
    } = Params::parse();

    let evidence = {
        // Get binary evidence using protoc
        let vec = Command::new("protoc")
            .args(&[
                "--encode=oak.attestation.v1.Evidence",
                "./proto/attestation/evidence.proto",
            ])
            .stdin(std::fs::File::open(evidence).expect("couldn't open evidence"))
            .output()
            .expect("failed to parse text proto")
            .stdout;
        // let vec = fs::read(evidence).expect("couldn't open evidence");
        Evidence::decode(vec.as_slice()).expect("couldn't decode evidence")
    };
    // println!("Evidence: {:?}", evidence);

    let endorsements = {
        // Get binary endorsements using protoc
        let vec = Command::new("protoc")
            .args(&[
                "--encode=oak.attestation.v1.Endorsements",
                "./proto/attestation/endorsement.proto",
            ])
            .stdin(std::fs::File::open(endorsements).expect("couldn't open endorsements"))
            .output()
            .expect("failed to parse text proto")
            .stdout;
        // let vec = fs::read(endorsements).expect("couldn't open endorsements");
        Endorsements::decode(vec.as_slice()).expect("couldn't decode endorsements")
    };
    // println!("Endorsements: {:?}", endorsements);

    let reference_values = {
        let skip = BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        let text_skip = TextReferenceValue {
            r#type: Some(text_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        let regex_skip = RegexReferenceValue {
            r#type: Some(regex_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        // let kernel_skip = KernelBinaryReferenceValue {
        //     r#type: Some(kernel_binary_reference_value::Type::Skip(
        //         SkipVerification::default(),
        //     )),
        // };
        let kernel_binary_reference_value = KernelBinaryReferenceValue {
            r#type: Some(kernel_binary_reference_value::Type::Digests(KernelDigests {
                image: Some(Digests { digests: vec![kernel_image_measurement] }),
                setup_data: Some(Digests { digests: vec![kernel_setup_data_measurement] }),
            })),
        };

        let _amd_sev = AmdSevReferenceValues {
            min_tcb_version: None,
            allow_debug: false,
            stage0: Some(initial_measurement),
        };
        let insecure = oak_proto_rust::oak::attestation::v1::InsecureReferenceValues {};

        let root_layer = RootLayerReferenceValues {
            // amd_sev: Some(amd_sev),
            insecure: Some(insecure),
            ..Default::default()
        };

        #[allow(deprecated)]
        let kernel_layer = KernelLayerReferenceValues {
            kernel: Some(kernel_binary_reference_value),
            // kernel: Some(kernel_image_measurement),
            // kernel: Some(kernel_skip.clone()),
            kernel_cmd_line_text: Some(text_skip.clone()),
            init_ram_fs: Some(skip.clone()),
            memory_map: Some(skip.clone()),
            acpi: Some(skip.clone()),
            // Deprecated fields.
            kernel_setup_data: Some(skip.clone()),
            kernel_image: Some(skip.clone()),
            kernel_cmd_line_regex: Some(regex_skip.clone()),
            kernel_cmd_line: Some(skip.clone()),
        };

        let system_layer = SystemLayerReferenceValues {
            system_image: Some(system_image_measurement),
            // system_image: Some(skip.clone()),
        };

        let container_layer = ContainerLayerReferenceValues {
            binary: Some(application_measurement),
            configuration: Some(skip.clone()),
        };

        let reference_values = OakContainersReferenceValues {
            root_layer: Some(root_layer),
            kernel_layer: Some(kernel_layer),
            system_layer: Some(system_layer),
            container_layer: Some(container_layer),
        };
        ReferenceValues {
            r#type: Some(reference_values::Type::OakContainers(
                reference_values,
            )),
        }
    };

    // Verify attestation.
    let extracted_evidence = verify(NOW_UTC_MILLIS, &evidence, &endorsements, &reference_values);
    let attestation_results = to_attestation_results(&extracted_evidence);

    match attestation_results.status() {
        Status::Success => println!("✅ attestation verification successful."),
        Status::GenericFailure => {
            eprintln!(
                "🚫 Couldn't verify endorsed evidence: code={} reason={}",
                attestation_results.status as i32, attestation_results.reason
            );
        }
        Status::Unspecified => eprintln!("Illegal status code in attestation results"),
    }

    // Verify claim signature.
    let claim = fs::read(claim).expect("couldn't open claim");
    let claim_signature = fs::read(claim_signature).expect("couldn't open claim signature");

    #[allow(deprecated)]
    let verifying_key = VerifyingKey::from_sec1_bytes(
        attestation_results.signing_public_key.as_ref()
    ).expect("couldn't parse signing key");

    let verifier = VerifierKeyHandle { inner: verifying_key };
    match verifier.verify(&claim, &Signature { signature: claim_signature }) {
        Ok(()) => println!("✅ claim signature is correct.",),
        Err(error) => eprintln!("🚫 couldn't verify claim signature: {:?}", error),
    }
}
