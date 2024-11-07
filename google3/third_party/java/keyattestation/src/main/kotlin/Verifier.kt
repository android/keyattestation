package com.android.keyattestation.verifier

import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import com.google.common.time.TimeSource
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
  ) : VerificationResult

  data object ChallengeMismatch : VerificationResult

  data object PathValidationFailure : VerificationResult

  data object ChainParsingFailure : VerificationResult

  data object ExtensionParsingFailure : VerificationResult
}

/**
 * Verifier for Android Key Attestation certificate chain.
 *
 * https://developer.android.com/privacy-and-security/security-key-attestation
 *
 * @param anchor a [TrustAnchor] to use for certificate path verification.
 */
// TODO: b/356234568 - Verify intermediate certificate revocation status.
class Verifier(private val anchors: Set<TrustAnchor>) {
  init {
    Security.addProvider(KeyAttestationProvider())
  }

  private val certPathValidator = CertPathValidator.getInstance("KeyAttestation")

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
    val pathValidationResult =
      try {
        val params =
          PKIXParameters(anchors).apply { date = Date.from(TimeSource.system().instant()) }
        certPathValidator.validate(certPath, params) as PKIXCertPathValidatorResult
      } catch (e: CertPathValidatorException) {
        return VerificationResult.PathValidationFailure
      }

    val keyDescription =
      try {
        checkNotNull(certPath.leafCert().keyDescription()) { "Key attestation extension not found" }
      } catch (e: Exception) {
        return VerificationResult.ExtensionParsingFailure
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
        return VerificationResult.ExtensionParsingFailure
      }
    val rootOfTrust =
      keyDescription.teeEnforced.rootOfTrust ?: return VerificationResult.ExtensionParsingFailure
    return VerificationResult.Success(
      pathValidationResult.publicKey,
      keyDescription.attestationChallenge,
      securityLevel,
      rootOfTrust.verifiedBootState,
    )
  }
}
