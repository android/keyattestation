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
  CERTIFICATE_AFTER_TARGET,
  TARGET_MISSING_ATTESTATION_EXTENSION,
  ADDITIONAL_ATTESTATION_EXTENSION,
  KEY_ORIGIN_NOT_GENERATED,
  MISMATCHED_SECURITY_LEVELS,
  ROOT_OF_TRUST_MISSING,
  UNKNOWN_TAG_NUMBER,
}
