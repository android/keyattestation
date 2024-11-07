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
