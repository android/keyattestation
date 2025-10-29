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

import com.android.keyattestation.verifier.KeyAttestationReason
import com.android.keyattestation.verifier.testing.CertLists
import com.android.keyattestation.verifier.testing.Certs.rootAnchor as testAnchor
import com.android.keyattestation.verifier.testing.Chains
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.TestUtils.prodAnchors
import com.google.common.truth.Truth.assertThat
import java.security.InvalidAlgorithmParameterException
import java.security.Security
import java.security.cert.CertPathParameters
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertPathValidatorException.BasicReason
import java.security.cert.Certificate
import java.security.cert.PKIXCertPathChecker
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.PKIXReason
import kotlin.test.assertFailsWith
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class KeyAttestationCertPathValidatorTest {
  private val certPathValidator = CertPathValidator.getInstance("KeyAttestation")
  private val pkixCertPathValidator = CertPathValidator.getInstance("PKIX")
  private val prodParams = PKIXParameters(prodAnchors)
  private val testParams =
    PKIXParameters(setOf(testAnchor)).apply { date = FakeCalendar.DEFAULT.today() }

  @Test
  fun nullCertPath_throwsInvalidAlgorithmParameterException() {
    assertFailsWith<InvalidAlgorithmParameterException> {
      certPathValidator.validate(null, testParams)
    }
    // The PKIXValidator throws a NPE if the cert path is null, artistic license was taken in not
    // replicating that.
    assertFailsWith<NullPointerException> { pkixCertPathValidator.validate(null, testParams) }
  }

  @Test
  fun nullParameters_throwsInvalidAlgorithmParameterException() {
    assertFailsWith<InvalidAlgorithmParameterException> {
      certPathValidator.validate(Chains.validFactoryProvisioned, null)
    }
    assertFailsWith<InvalidAlgorithmParameterException> {
      pkixCertPathValidator.validate(Chains.validFactoryProvisioned, null)
    }
  }

  @Test
  fun wrongParameterType_throwsInvalidAlgorithmParameterException() {
    val params = CertPathParameters { throw UnsupportedOperationException() }
    assertFailsWith<InvalidAlgorithmParameterException> {
      certPathValidator.validate(Chains.validFactoryProvisioned, params)
    }
    assertFailsWith<InvalidAlgorithmParameterException> {
      pkixCertPathValidator.validate(Chains.validFactoryProvisioned, params)
    }
  }

  @Test
  fun nullDate_throwsCertPathValidatorException() {
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(
          Chains.validFactoryProvisioned,
          PKIXParameters(setOf(testAnchor)),
        )
      }
    val pkixException =
      assertFailsWith<CertPathValidatorException> {
        pkixCertPathValidator.validate(
          Chains.validFactoryProvisioned,
          PKIXParameters(setOf(testAnchor)),
        )
      }
    assertThat(exception.reason).isEqualTo(BasicReason.EXPIRED)
    assertThat(pkixException.reason).isEqualTo(BasicReason.EXPIRED)
  }

  @Test
  fun validChain_returnsSuccess() {
    val certPath = Chains.validFactoryProvisioned
    val result = certPathValidator.validate(certPath, testParams) as PKIXCertPathValidatorResult
    assertThat(result.trustAnchor).isEqualTo(testAnchor)
    assertThat(result.policyTree).isNull()
    assertThat(result.publicKey).isEqualTo(certPath.certificates.first().publicKey)
  }

  @Test
  fun remotelyProvisioned_returnsSuccess() {
    val certPath = Chains.validRemotelyProvisioned
    val result = certPathValidator.validate(certPath, testParams) as PKIXCertPathValidatorResult
    assertThat(result.trustAnchor).isEqualTo(testAnchor)
    assertThat(result.policyTree).isNull()
    assertThat(result.publicKey).isEqualTo(certPath.certificates.first().publicKey)
  }

  @Test
  fun additionalAnchors_returnsSuccess() {
    val certPath = Chains.validFactoryProvisioned
    val moreAnchors = prodAnchors.union(setOf(testAnchor))
    val params = PKIXParameters(moreAnchors).apply { date = FakeCalendar.DEFAULT.today() }
    val result = certPathValidator.validate(certPath, params) as PKIXCertPathValidatorResult
    assertThat(result.trustAnchor).isEqualTo(testAnchor)
    assertThat(result.policyTree).isNull()
    assertThat(result.publicKey).isEqualTo(certPath.certificates.first().publicKey)
  }

  @Test
  fun expiredLeaf_returnsSuccess() {
    val certPath = Chains.expiredLeaf
    val result = certPathValidator.validate(certPath, testParams) as PKIXCertPathValidatorResult
    assertThat(result.trustAnchor).isEqualTo(testAnchor)
    assertThat(result.policyTree).isNull()
    assertThat(result.publicKey).isEqualTo(certPath.certificates.first().publicKey)
  }

  @Test
  fun multipleWrongAnchors_throwsCertPathValidatorException() {
    val certPath = Chains.validFactoryProvisioned
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, prodParams)
      }
    val pkixException =
      assertFailsWith<CertPathValidatorException> {
        pkixCertPathValidator.validate(certPath, prodParams)
      }
    assertThat(prodParams.trustAnchors.size).isAtLeast(2)
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
    assertThat(pkixException.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun singleWrongAnchor_throwsCertPathValidatorException() {
    val params =
      PKIXParameters(setOf(prodAnchors.first())).apply { date = FakeCalendar.DEFAULT.today() }
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(Chains.validFactoryProvisioned, params)
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun wrongIssuer_throwsCertPathValidatorException() {
    val certPath = Chains.wrongIssuer
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, testParams)
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NAME_CHAINING)
  }

  @Test
  fun wrongSignature_throwsCertPathValidatorException() {
    val certPath = Chains.wrongSignature
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, testParams)
      }
    assertThat(exception.reason).isEqualTo(BasicReason.INVALID_SIGNATURE)
  }

  @Test
  fun wrongAlgorithm_throwsCertPathValidatorException() {
    val certPath = Chains.wrongAlgorithm
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, testParams)
      }
    assertThat(exception.reason).isEqualTo(BasicReason.UNSPECIFIED)
  }

  @Test
  fun notYetValid_throwsCertPathValidatorException() {
    val certPath = Chains.notYetValid
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, testParams)
      }
    assertThat(exception.reason).isEqualTo(BasicReason.NOT_YET_VALID)
  }

  @Test
  fun expired_throwsCertPathValidatorException() {
    val certPath = Chains.expired
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, testParams)
      }
    assertThat(exception.reason).isEqualTo(BasicReason.EXPIRED)
  }

  @Test
  fun forgedKeybox_throwsCertPathValidatorException() {
    val certPath = Chains.forgedKeybox
    assertFailsWith<CertPathValidatorException> { certPathValidator.validate(certPath, testParams) }
  }

  @Test
  fun extraLeaf_throwsCertPathValidatorException() {
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(KeyAttestationCertPath(CertLists.extended), testParams)
      }
    assertThat(exception.reason)
      .isEqualTo(KeyAttestationReason.CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION)
  }

  @Test
  fun certAfterLeaf_throwsCertPathValidatorException() {
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(KeyAttestationCertPath(CertLists.certAfterTarget), testParams)
      }
    assertThat(exception.reason).isEqualTo(KeyAttestationReason.CHAIN_EXTENDED_FOR_KEY)
  }

  @Test
  fun additionalCertPathChecker_isCalled() {
    assertFailsWith<FakeChecker.Exception> {
      certPathValidator.validate(
        Chains.validFactoryProvisioned,
        testParams.apply { addCertPathChecker(FakeChecker()) },
      )
    }
  }

  companion object {
    @BeforeClass
    @JvmStatic
    fun setUpClass() {
      Security.addProvider(KeyAttestationProvider())
    }
  }
}

class FakeChecker : PKIXCertPathChecker() {
  override fun init(forward: Boolean) = Unit

  override fun isForwardCheckingSupported() = false

  override fun getSupportedExtensions() = null

  override fun check(cert: Certificate, unresolvedCritExts: MutableCollection<String>) =
    throw Exception()

  class Exception : RuntimeException()
}
