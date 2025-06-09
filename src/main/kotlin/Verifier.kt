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
    val attestedDeviceIds: DeviceIdentity,
  ) : VerificationResult

  data object ChallengeMismatch : VerificationResult

  data class PathValidationFailure(val cause: Exception) : VerificationResult

  data class ChainParsingFailure(val cause: Exception) : VerificationResult

  data class ExtensionParsingFailure(val cause: Exception) : VerificationResult

  data class ExtensionConstraintViolation(val cause: String) : VerificationResult
}

/** Interface for logging info level key attestation events and information. */
interface LogHook {
  fun logVerificationEvent(verificationEvent: VerificationEvent)
}

data class VerificationEvent(
  val inputChain: List<X509Certificate>,
  val result: VerificationResult,
  val keyDescription: KeyDescription? = null,
  val provisioningInfoMap: ProvisioningInfoMap? = null,
  val certSerialNumbers: List<String>? = null,
  val infoMessages: List<String>? = null,
)

/**
 * Verifier for Android Key Attestation certificate chain.
 *
 * https://developer.android.com/privacy-and-security/security-key-attestation
 *
 * @param anchor a [TrustAnchor] to use for certificate path verification.
 */
// TODO: b/356234568 - Verify intermediate certificate revocation status.
@ThreadSafe
open class Verifier(
  private val trustAnchorsSource: () -> Set<TrustAnchor>,
  private val revokedSerialsSource: () -> Set<String>,
  private val instantSource: InstantSource,
) {
  init {
    Security.addProvider(KeyAttestationProvider())
  }

  /**
   * Verifies an Android Key Attestation certificate chain.
   *
   * @param chain The attestation certificate chain to verify.
   * @param challengeChecker The challenge checker to use for additional challenge validation.
   * @return [VerificationResult]
   */
  @JvmOverloads
  fun verify(
    chain: List<X509Certificate>,
    challengeChecker: ChallengeChecker? = null,
    log: LogHook? = null,
  ): VerificationResult {
    val certPath =
      try {
        KeyAttestationCertPath(chain)
      } catch (e: Exception) {
        val result = VerificationResult.ChainParsingFailure(e)
        log?.logVerificationEvent(VerificationEvent(inputChain = chain, result = result))
        return result
      }
    val verificationEvent = internalVerify(certPath, challengeChecker)
    log?.logVerificationEvent(verificationEvent)
    return verificationEvent.result
  }

  /**
   * Verifies an Android Key Attestation certificate chain.
   *
   * @param chain The attestation certificate chain to verify.
   * @param challengeChecker The challenge checker to use for additional validation of the challenge
   *   in the attestation chain.
   * @return [VerificationEvent]
   *
   * TODO: b/366058500 - Make the challenge required after Apparat's changes are rollback safe.
   */
  fun verify(
    certPath: KeyAttestationCertPath,
    challengeChecker: ChallengeChecker? = null,
    log: LogHook? = null,
  ): VerificationResult {
    val verificationEvent = internalVerify(certPath, challengeChecker)
    log?.logVerificationEvent(verificationEvent)
    return verificationEvent.result
  }

  internal fun internalVerify(
    certPath: KeyAttestationCertPath,
    challengeChecker: ChallengeChecker? = null,
  ): VerificationEvent {
    val serialNumbers =
      certPath.certificatesWithAnchor.subList(1, certPath.certificatesWithAnchor.size).map {
        it.serialNumber.toString(16)
      }
    val certPathValidator = CertPathValidator.getInstance("KeyAttestation")
    val certPathParameters =
      PKIXParameters(trustAnchorsSource()).apply {
        date = Date.from(instantSource.instant())
        addCertPathChecker(RevocationChecker(revokedSerialsSource()))
      }

    val deviceInformation =
      if (certPath.provisioningMethod() == ProvisioningMethod.REMOTELY_PROVISIONED) {
        certPath.attestationCert().provisioningInfo()
      } else {
        null
      }
    val pathValidationResult =
      try {
        certPathValidator.validate(certPath, certPathParameters) as PKIXCertPathValidatorResult
      } catch (e: CertPathValidatorException) {
        return VerificationEvent(
          inputChain = certPath.getCertificates(),
          result = VerificationResult.PathValidationFailure(e),
          certSerialNumbers = serialNumbers,
          provisioningInfoMap = deviceInformation,
        )
      }

    val keyDescription =
      try {
        checkNotNull(certPath.leafCert().keyDescription()) { "Key attestation extension not found" }
      } catch (e: Exception) {
        return VerificationEvent(
          inputChain = certPath.getCertificates(),
          result = VerificationResult.ExtensionParsingFailure(e),
          certSerialNumbers = serialNumbers,
          provisioningInfoMap = deviceInformation,
        )
      }

    val infoMessages = keyDescription.infoMessages

    if (
      challengeChecker != null &&
        !challengeChecker.checkChallenge(keyDescription.attestationChallenge)
    ) {
      return VerificationEvent(
        inputChain = certPath.getCertificates(),
        result = VerificationResult.ChallengeMismatch,
        certSerialNumbers = serialNumbers,
        keyDescription = keyDescription,
        infoMessages = infoMessages,
        provisioningInfoMap = deviceInformation,
      )
    }

    if (
      keyDescription.hardwareEnforced.origin == null ||
        keyDescription.hardwareEnforced.origin != Origin.GENERATED
    ) {
      return VerificationEvent(
        result =
          VerificationResult.ExtensionConstraintViolation(
            "hardwareEnforced.origin is not GENERATED: ${keyDescription.hardwareEnforced.origin}"
          ),
        inputChain = certPath.getCertificates(),
        certSerialNumbers = serialNumbers,
        keyDescription = keyDescription,
        infoMessages = infoMessages,
        provisioningInfoMap = deviceInformation,
      )
    }

    val securityLevel =
      if (keyDescription.attestationSecurityLevel == keyDescription.keyMintSecurityLevel) {
        keyDescription.attestationSecurityLevel
      } else {
        return VerificationEvent(
          result =
            VerificationResult.ExtensionConstraintViolation(
              "attestationSecurityLevel != keymintSecurityLevel: ${keyDescription.attestationSecurityLevel} != ${keyDescription.keyMintSecurityLevel}"
            ),
          inputChain = certPath.getCertificates(),
          certSerialNumbers = serialNumbers,
          keyDescription = keyDescription,
          infoMessages = infoMessages,
          provisioningInfoMap = deviceInformation,
        )
      }
    val rootOfTrust =
      keyDescription.hardwareEnforced.rootOfTrust
        ?: return VerificationEvent(
          result =
            VerificationResult.ExtensionConstraintViolation("hardwareEnforced.rootOfTrust is null"),
          keyDescription = keyDescription,
          inputChain = certPath.getCertificates(),
          certSerialNumbers = serialNumbers,
          infoMessages = infoMessages,
          provisioningInfoMap = deviceInformation,
        )
    return VerificationEvent(
      result =
        VerificationResult.Success(
          pathValidationResult.publicKey,
          keyDescription.attestationChallenge,
          securityLevel,
          rootOfTrust.verifiedBootState,
          deviceInformation,
          DeviceIdentity.parseFrom(keyDescription),
        ),
      inputChain = certPath.getCertificates(),
      certSerialNumbers = serialNumbers,
      keyDescription = keyDescription,
      infoMessages = infoMessages,
      provisioningInfoMap = deviceInformation,
    )
  }
}
