/*
 * Copyright 2025 Google LLC
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

package com.android.keyattestation.verifier

import androidx.annotation.RequiresApi
import java.security.cert.CertPathValidatorException

/** Reasons why a certificate chain could not be verified which are specific to key attestation. */
@RequiresApi(24)
enum class KeyAttestationReason : CertPathValidatorException.Reason {
  // Certificate chain contains a certificate after the target certificate.
  // This likely indicates that an attacker is trying to get the verifier to
  // accept an attacker-controlled key.
  CHAIN_EXTENDED_FOR_KEY,
  // The key description is missing from the expected certificate.
  // An Android key attestation chain without a key description is malformed.
  TARGET_MISSING_ATTESTATION_EXTENSION,
  // Certificate chain contains a certificate other than the target certificate with an attestation
  // extension. This likely indicates that an attacker is trying to manipulate the key and
  // device properties.
  CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION,
  // The key was not generated. The verifier cannot know that the key has always been in the
  // secure environment.
  KEY_ORIGIN_NOT_GENERATED,
  // The attestation and the KeyMint security levels do not match.
  // This likely indicates that the attestation was generated in software and so cannot be trusted.
  MISMATCHED_SECURITY_LEVELS,
  // The key description is missing the root of trust.
  // An Android key attestation chain without a root of trust is malformed.
  ROOT_OF_TRUST_MISSING,
  // There was an error parsing the key description and an unknown tag number was encountered.
  UNKNOWN_TAG_NUMBER,
}
