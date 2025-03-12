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

package com.android.keyattestation.verifier

import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import com.android.keyattestation.verifier.provider.ProvisioningMethod
import com.android.keyattestation.verifier.provider.RevocationChecker
import com.google.errorprone.annotations.ThreadSafe
import com.google.protobuf.ByteString
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/** The result of verifying an Android Key Attestation certificate chain. */
sealed interface VerificationResult {
  data class Success(
    val publicKey: PublicKey,
    val challenge: ByteString,
    val securityLevel: SecurityLevel,
    val verifiedBootState: VerifiedBootState,
    val deviceInformation: ProvisioningInfoMap?,
  ) : VerificationResult

  data object ChallengeMismatch : VerificationResult

  data object PathValidationFailure : VerificationResult

  data object ChainParsingFailure : VerificationResult

  data class ExtensionParsingFailure(val cause: Exception) : VerificationResult

  data class ExtensionConstraintViolation(val cause: String) : VerificationResult
}

/**
 * Verifier for Android Key Attestation certificate chain.
 *
 * https://developer.android.com/privacy-and-security/security-key-attestation
 *
 * @param anchor a [TrustAnchor] to use for certificate path verification.
 */
// TODO: b/356234568 - Verify intermediate certificate revocation status.
@ThreadSafe
class Verifier(
  private val trustAnchorsSource: () -> Set<TrustAnchor>,
  private val revokedSerialsSource: () -> Set<String>,
  private val instantSource: InstantSource,
) {
  init {
    Security.addProvider(KeyAttestationProvider())
  }

  fun verify(chain: List<X509Certificate>, challenge: ByteArray? = null): VerificationResult {
    val certPath =
      try {
        KeyAttestationCertPath(chain)
      } catch (e: Exception) {
        return VerificationResult.ChainParsingFailure
      }
    return verify(certPath, challenge)
  }

  /**
   * Verifies an Android Key Attestation certificate chain.
   *
   * @param chain The attestation certificate chain to verify.
   * @return [VerificationResult]
   *
   * TODO: b/366058500 - Make the challenge required after Apparat's changes are rollback safe.
   */
  @JvmOverloads
  fun verify(certPath: KeyAttestationCertPath, challenge: ByteArray? = null): VerificationResult {
    val certPathValidator = CertPathValidator.getInstance("KeyAttestation")
    val certPathParameters =
      PKIXParameters(trustAnchorsSource()).apply {
        date = Date.from(instantSource.instant())
        addCertPathChecker(RevocationChecker(revokedSerialsSource()))
      }
    val pathValidationResult =
      try {
        certPathValidator.validate(certPath, certPathParameters) as PKIXCertPathValidatorResult
      } catch (e: CertPathValidatorException) {
        return VerificationResult.PathValidationFailure
      }

    val keyDescription =
      try {
        checkNotNull(certPath.leafCert().keyDescription()) { "Key attestation extension not found" }
      } catch (e: Exception) {
        return VerificationResult.ExtensionParsingFailure(e)
      }

    if (
      challenge != null &&
        keyDescription.attestationChallenge.asReadOnlyByteBuffer() != ByteBuffer.wrap(challenge)
    ) {
      return VerificationResult.ChallengeMismatch
    }

    val securityLevel =
      if (keyDescription.attestationSecurityLevel == keyDescription.keymasterSecurityLevel) {
        keyDescription.attestationSecurityLevel
      } else {
        return VerificationResult.ExtensionConstraintViolation(
          "attestationSecurityLevel != keymasterSecurityLevel: ${keyDescription.attestationSecurityLevel} != ${keyDescription.keymasterSecurityLevel}"
        )
      }
    val rootOfTrust =
      keyDescription.teeEnforced.rootOfTrust
        ?: return VerificationResult.ExtensionConstraintViolation("teeEnforced.rootOfTrust is null")
    val deviceInformation =
      if (certPath.provisioningMethod() == ProvisioningMethod.REMOTELY_PROVISIONED) {
        certPath.attestationCert().provisioningInfo()
      } else {
        null
      }
    return VerificationResult.Success(
      pathValidationResult.publicKey,
      keyDescription.attestationChallenge,
      securityLevel,
      rootOfTrust.verifiedBootState,
      deviceInformation,
    )
  }
}
