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
import com.google.protobuf.kotlin.toByteString
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

  data class PathValidationFailure(val cause: CertPathValidatorException) : VerificationResult

  data class ChainParsingFailure(val cause: Exception) : VerificationResult

  data class ExtensionParsingFailure(val cause: Exception) : VerificationResult

  data class ExtensionConstraintViolation(val cause: String) : VerificationResult
}

/** Interface for logging info level key attestation events and information. */
interface LogHook {

  /**
   * Logs the certificate chain which is being verified. Called for each call to [verify].
   *
   * @param inputChain The certificate chain which is being verified.
   */
  fun logInputChain(inputChain: List<ByteString>)

  /**
   * Logs the result of the verification. Called for each call to [verify].
   *
   * @param result The result of the verification.
   */
  fun logResult(result: VerificationResult)

  /**
   * Logs the key description of the leaf certificate. Called if [verify] reaches the point where
   * the key description is parsed.
   *
   * @param keyDescription The key description of the leaf certificate.
   */
  fun logKeyDescription(keyDescription: KeyDescription)

  /**
   * Logs the provisioning info map extension of the attestation certificate. Called if [verify]
   * reaches the point where the provisioning info map is parsed, if present in the attestation
   * certificate.
   *
   * @param provisioningInfoMap The provisioning info map extension of the leaf certificate.
   */
  fun logProvisioningInfoMap(provisioningInfoMap: ProvisioningInfoMap)

  /**
   * Logs the serial numbers of the intermediate certificates in the certificate chain. Called if
   * [verify] reaches the point where the certificate chain is parsed.
   *
   * @param certSerialNumbers The serial numbers of the intermediate certificates in the certificate
   *   chain.
   */
  fun logCertSerialNumbers(certSerialNumbers: List<String>)

  /**
   * Logs an info level message. May be called throughout the verification process.
   *
   * @param infoMessage The info level message to log.
   */
  fun logInfoMessage(infoMessage: String)
}

/**
 * Verifier for Android Key Attestation certificate chain.
 *
 * https://developer.android.com/privacy-and-security/security-key-attestation
 *
 * @param anchor a [TrustAnchor] to use for certificate path verification.
 */
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
        log?.logInputChain(chain.map { it.getEncoded().toByteString() })
        log?.logResult(result)
        return result
      }
    val result = internalVerify(certPath, challengeChecker, log)
    log?.logResult(result)
    return result
  }

  /**
   * Verifies an Android Key Attestation certificate chain.
   *
   * @param chain The attestation certificate chain to verify.
   * @param challengeChecker The challenge checker to use for additional validation of the challenge
   *   in the attestation chain.
   * @return [VerificationEvent]
   */
  @JvmOverloads
  fun verify(
    certPath: KeyAttestationCertPath,
    challengeChecker: ChallengeChecker? = null,
    log: LogHook? = null,
  ): VerificationResult {
    val result = internalVerify(certPath, challengeChecker, log)
    log?.logResult(result)
    return result
  }

  internal fun internalVerify(
    certPath: KeyAttestationCertPath,
    challengeChecker: ChallengeChecker? = null,
    log: LogHook? = null,
  ): VerificationResult {
    log?.logInputChain(certPath.certificatesWithAnchor.map { it.getEncoded().toByteString() })
    log?.logCertSerialNumbers(
      certPath.certificatesWithAnchor.subList(1, certPath.certificatesWithAnchor.size).map {
        it.serialNumber.toString(16)
      }
    )
    val certPathValidator = CertPathValidator.getInstance("KeyAttestation")
    val certPathParameters =
      PKIXParameters(trustAnchorsSource()).apply {
        date = Date.from(instantSource.instant())
        addCertPathChecker(RevocationChecker(revokedSerialsSource()))
      }

    val deviceInformation =
      if (certPath.provisioningMethod() == ProvisioningMethod.REMOTELY_PROVISIONED) {
        try {
          certPath.attestationCert().provisioningInfo()
        } catch (e: Exception) {
          log?.logInfoMessage("Failed to parse provisioning info map: ${e.message}")
          null
        }
      } else {
        null
      }
    deviceInformation?.let { log?.logProvisioningInfoMap(it) }
    val pathValidationResult =
      try {
        certPathValidator.validate(certPath, certPathParameters) as PKIXCertPathValidatorResult
      } catch (e: CertPathValidatorException) {
        return VerificationResult.PathValidationFailure(e)
      }

    val keyDescription =
      try {
        checkNotNull(
          KeyDescription.parseFrom(certPath.leafCert(), { msg -> log?.logInfoMessage(msg) })
        ) {
          "Key attestation extension not found"
        }
      } catch (e: Exception) {
        return VerificationResult.ExtensionParsingFailure(e)
      }
    log?.logKeyDescription(keyDescription)
    if (
      challengeChecker != null &&
        !challengeChecker.checkChallenge(keyDescription.attestationChallenge)
    ) {
      return VerificationResult.ChallengeMismatch
    }

    if (
      keyDescription.hardwareEnforced.origin == null ||
        keyDescription.hardwareEnforced.origin != Origin.GENERATED
    ) {
      return VerificationResult.ExtensionConstraintViolation(
        "origin != GENERATED: ${keyDescription.hardwareEnforced.origin}"
      )
    }

    val securityLevel =
      if (keyDescription.attestationSecurityLevel == keyDescription.keyMintSecurityLevel) {
        keyDescription.attestationSecurityLevel
      } else {
        return VerificationResult.ExtensionConstraintViolation(
          "attestationSecurityLevel != keyMintSecurityLevel: ${keyDescription.attestationSecurityLevel} != ${keyDescription.keyMintSecurityLevel}"
        )
      }
    val rootOfTrust =
      keyDescription.hardwareEnforced.rootOfTrust
        ?: return VerificationResult.ExtensionConstraintViolation(
          "hardwareEnforced.rootOfTrust is null"
        )
    return VerificationResult.Success(
      pathValidationResult.publicKey,
      keyDescription.attestationChallenge,
      securityLevel,
      rootOfTrust.verifiedBootState,
      deviceInformation,
      DeviceIdentity.parseFrom(keyDescription),
    )
  }
}
