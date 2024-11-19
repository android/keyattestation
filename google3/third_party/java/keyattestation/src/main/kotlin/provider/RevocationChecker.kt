/*
 * Copyright 2024 Google LLC
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

package com.android.keyattestation.verifier.provider

import java.security.cert.CertPathValidatorException
import java.security.cert.CertPathValidatorException.BasicReason
import java.security.cert.Certificate
import java.security.cert.PKIXRevocationChecker
import java.security.cert.X509Certificate

/**
 * A [PKIXRevocationChecker] implementation for Android Key Attestation.
 *
 * Currently, this class is a clone of the as-built revocation checker from KAVS. It is only
 * intended to be for migrating the bespoke KAVS path validation logic to this provider.
 *
 * http://google3/java/com/google/wireless/android/work/boq/unspoofableid/common/VerifyCertificateChain.java;l=107;rcl=677835266
 */
class RevocationChecker(private val revokedSerials: Set<String>) : PKIXRevocationChecker() {
  override fun init(forward: Boolean) {
    if (forward) throw CertPathValidatorException("forward checking not supported")
  }

  override fun isForwardCheckingSupported() = false

  override fun getSupportedExtensions() = null

  override fun getSoftFailExceptions() = listOf<CertPathValidatorException>()

  override fun check(cert: Certificate, unresolvedCritExts: MutableCollection<String>) {
    require(cert is X509Certificate)

    if (revokedSerials.contains(cert.serialNumber.toString(16))) {
      // TODO: b/356234568 - Surface the revocation reason.
      throw CertPathValidatorException(
        "Certificate has been revoked",
        null,
        null,
        -1,
        BasicReason.REVOKED,
      )
    }
  }
}
