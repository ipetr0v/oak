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

#ifndef OAK_COMMON_AUTHORITY_H_
#define OAK_COMMON_AUTHORITY_H_

#include "asylo/identity/enclave_assertion_authority_config.pb.h"

namespace oak {

// Class with static methods for authority initialization.
class Authority {
 // TODO: Consider hiding most of the logic in private methods
 public:
  static asylo::EnclaveAssertionAuthorityConfig CreateNullAssertionAuthorityConfig();
  static asylo::EnclaveAssertionAuthorityConfig CreateSgxLocalAssertionAuthorityConfig(
      std::string attestation_domain="A 16-byte domain");

  // This method sets up the necessary global state for Asylo to be able to validate authorities
  // (e.g. root CAs, remote attestation endpoints, etc.).
  static void InitializeAssertionAuthorities();
};

}  // namespace oak

#endif  // OAK_COMMON_AUTHORITY_H_
