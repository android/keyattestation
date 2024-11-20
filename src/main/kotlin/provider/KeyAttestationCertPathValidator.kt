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

import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.PublicKey
import java.security.SignatureException
import java.security.cert.CertPath
import java.security.cert.CertPathParameters
import java.security.cert.CertPathValidatorException
import java.security.cert.CertPathValidatorException.BasicReason
import java.security.cert.CertPathValidatorResult
import java.security.cert.CertPathValidatorSpi
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.PKIXCertPathChecker
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.PKIXReason
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * A [CertPathValidatorSpi] for verifying Android Key Attestation certificate chains.
 *
 * Older Android devices produce Key Attestation certificate chains that do not fully conform to RFC
 * 5280 and thus cannot be validating using [sun.security.provider.certpath.PKIXCertPathValidator].
 * This provider implements a more permissive [CertPathValidatorSpi] implementation that is able to
 * validate these chains.
 *
 * See go/how-to-validate-key-attestations for details for how to verify Android Key Attestation
 * certificate chains.
 */
class KeyAttestationCertPathValidator : CertPathValidatorSpi() {
  override fun engineValidate(
    certPath: CertPath?,
    params: CertPathParameters?,
  ): CertPathValidatorResult {
    if (certPath == null) {
      throw InvalidAlgorithmParameterException("certPath is null")
    }
    if (certPath.type != "X.509") {
      throw InvalidAlgorithmParameterException(
        "CertPath must have type \"X.509\", was \"${certPath.type}\""
      )
    }
    if (params !is PKIXParameters) {
      throw InvalidAlgorithmParameterException("params must be an instance of PKIXParameters")
    }
    return validate(
      certPath,
      params.trustAnchors,
      params.certPathCheckers,
      params.date ?: Date(),
      params.sigProvider,
    )
  }

  private fun validate(
    certPath: CertPath,
    trustAnchors: Set<TrustAnchor>,
    extraCertPathCheckers: List<PKIXCertPathChecker>,
    date: Date,
    sigProvider: String?,
  ): CertPathValidatorResult {
    val certList = certPath.toCertList()
    val selector = X509CertSelector().apply { issuer = certList.first().issuerX500Principal }

    var lastException: CertPathValidatorException? = null
    for (anchor in trustAnchors) {
      if (anchor.trustedCert != null && !selector.match(anchor.trustedCert)) continue

      try {
        return validate(certPath, anchor, extraCertPathCheckers, date, sigProvider)
      } catch (e: CertPathValidatorException) {
        lastException = e
      }
    }

    if (lastException != null) {
      throw lastException
    } else {
      throw CertPathValidatorException(
        "No matching trust anchor found",
        null,
        null,
        -1,
        PKIXReason.NO_TRUST_ANCHOR,
      )
    }
  }

  private fun validate(
    certPath: CertPath,
    anchor: TrustAnchor,
    extraCertPathCheckers: List<PKIXCertPathChecker>,
    date: Date,
    sigProvider: String?,
  ): CertPathValidatorResult {
    val certList = certPath.toCertList()
    val pathLen = certPath.certificates.size
    val basicChecker = BasicChecker(anchor, pathLen, date, sigProvider)
    val certPathCheckers = listOf(basicChecker, *extraCertPathCheckers.toTypedArray())

    certList.forEachIndexed { idx, cert ->
      val unresolvedCritExts = cert.criticalExtensionOIDs ?: emptyList()
      if (idx == 0) certPathCheckers.forEach { it.init(false) }
      for (checker in certPathCheckers) {
        try {
          checker.check(cert, unresolvedCritExts)
        } catch (e: CertPathValidatorException) {
          throw CertPathValidatorException(
            e.message,
            e.cause ?: e,
            certPath,
            certList.size - (idx + 1),
            e.reason,
          )
        }
      }
    }

    return PKIXCertPathValidatorResult(anchor, /* policyTree= */ null, basicChecker.publicKey)
  }

  private fun CertPath.toCertList(): List<X509Certificate> =
    this.certificates.reversed().map {
      require(it is X509Certificate)
      it
    }
}

private class BasicChecker(
  anchor: TrustAnchor,
  val certPathLen: Int,
  val date: Date,
  val sigProvider: String?,
) : PKIXCertPathChecker() {
  private val trustedPublicKey = anchor.trustedCert?.publicKey ?: anchor.caPublicKey
  private val caName = anchor.trustedCert?.subjectX500Principal ?: anchor.ca
  private var prevPubKey: PublicKey? = null
  private var prevSubject: X500Principal? = null
  private var remainingCerts = 0

  /** The public key of the last certificate that was checked. */
  val publicKey: PublicKey
    get() = checkNotNull(prevPubKey)

  override fun init(forward: Boolean) {
    if (forward) throw CertPathValidatorException("forward checking not supported")
    prevPubKey = trustedPublicKey
    prevSubject = caName
    remainingCerts = certPathLen
  }

  override fun isForwardCheckingSupported() = false

  override fun getSupportedExtensions() = null

  override fun check(cert: Certificate, unresolvedCritExts: MutableCollection<String>) {
    remainingCerts--
    verifyNameChaining(cert as X509Certificate) // cert will always be an X509Certificate
    verifySignature(cert)
    verifyValidity(cert)
    prevPubKey = cert.publicKey
    prevSubject = cert.subjectX500Principal
  }

  private fun verifyNameChaining(cert: X509Certificate) {
    if (cert.issuerX500Principal != prevSubject) {
      throw CertPathValidatorException(
        "Subject/Issuer name chaining check failed",
        null,
        null,
        -1,
        PKIXReason.NAME_CHAINING,
      )
    }
  }

  private fun verifySignature(cert: X509Certificate) {
    try {
      cert.verify(prevPubKey, sigProvider)
    } catch (e: SignatureException) {
      throw CertPathValidatorException(
        "Signature check failed",
        e,
        null,
        -1,
        BasicReason.INVALID_SIGNATURE,
      )
    } catch (e: GeneralSecurityException) {
      /*
       * If the signing key has a different algorithm than the signature, InvalidKeyException will
       * be thrown instead of SignatureException. InvalidKeyException along with the other
       * exceptions that verify() throws are all subclasses of GeneralSecurityException.
       */
      throw CertPathValidatorException("Signature check failed", e)
    }
  }

  private fun verifyValidity(cert: X509Certificate) {
    /*
     * KAVS does not check the validity of the final certificate in the path. For the purposes of
     * migration this path validator is intended to be bug compatible with KAVS, so we do not check
     * the validity of the final certificate either.
     * http://google3/java/com/google/wireless/android/work/boq/unspoofableid/common/VerifyCertificateChain.java;l=173;rcl=679670181
     *
     * TODO: b/355190989 - explore if is viable to check the validity of the final certificate.
     */
    if (remainingCerts == 0) return
    try {
      cert.checkValidity(date)
    } catch (e: CertificateNotYetValidException) {
      throw CertPathValidatorException(
        "Validity check failed",
        e,
        null,
        -1,
        BasicReason.NOT_YET_VALID,
      )
    } catch (e: CertificateExpiredException) {
      throw CertPathValidatorException("Validity check failed", e, null, -1, BasicReason.EXPIRED)
    }
  }
}
