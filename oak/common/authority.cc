/*
 * Copyright 2019 The Project Oak Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "oak/common/authority.h"

#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/init.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"

namespace oak {

namespace {
// TODO: Use asylo/identity/enclave_assertion_authority_configs.cc when it will be public
constexpr size_t kAttestationDomainNameSize = 16;
}  // namespace

asylo::EnclaveAssertionAuthorityConfig Authority::CreateNullAssertionAuthorityConfig() {
  asylo::EnclaveAssertionAuthorityConfig authority_config;
  asylo::SetNullAssertionDescription(authority_config.mutable_description());
  return authority_config;
}

asylo::EnclaveAssertionAuthorityConfig Authority::CreateSgxLocalAssertionAuthorityConfig(
  std::string attestation_domain) {
  if (attestation_domain.size() != kAttestationDomainNameSize) {
      LOG(QFATAL) << "Attestation domain must be "
                  << kAttestationDomainNameSize
                  << " bytes in size";
  }

  asylo::EnclaveAssertionAuthorityConfig authority_config;
  asylo::SetSgxLocalAssertionDescription(authority_config.mutable_description());

  asylo::SgxLocalAssertionAuthorityConfig config;
  *config.mutable_attestation_domain() = std::move(attestation_domain);

  if (!config.SerializeToString(authority_config.mutable_config())) {
      LOG(QFATAL) << "Failed to serialize SgxLocalAssertionAuthorityConfig";
  }

  return authority_config;
}

void Authority::InitializeAssertionAuthorities() {
  LOG(INFO) << "Initializing assertion authorities";

  // TODO: Add remote Sgx Assertion Authority when available.
  std::vector<asylo::EnclaveAssertionAuthorityConfig> configs = {
      CreateNullAssertionAuthorityConfig(),
      CreateSgxLocalAssertionAuthorityConfig(),
  };

  asylo::Status status =
      asylo::InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end());
  if (!status.ok()) {
      LOG(QFATAL) << "Could not initialize assertion authorities";
  }

  LOG(INFO) << "Assertion authorities initialized";
}

}  // namespace oak
