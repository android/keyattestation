package com.google.wireless.android.security.attestationverifier.provider

import com.google.common.truth.Truth.assertThat
import com.google.wireless.android.security.attestationverifier.testing.Certs.rootAnchor as testAnchor
import com.google.wireless.android.security.attestationverifier.testing.Chains
import com.google.wireless.android.security.attestationverifier.testing.FakeCalendar
import com.google.wireless.android.security.attestationverifier.testing.TestUtils.prodAnchor
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
  private val prodParams = PKIXParameters(setOf(prodAnchor))
  private val testParams = PKIXParameters(setOf(testAnchor)).apply { date = FakeCalendar.today() }

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
      certPathValidator.validate(Chains.valid, null)
    }
    assertFailsWith<InvalidAlgorithmParameterException> {
      pkixCertPathValidator.validate(Chains.valid, null)
    }
  }

  @Test
  fun wrongParameterType_throwsInvalidAlgorithmParameterException() {
    val params = CertPathParameters { throw UnsupportedOperationException() }
    assertFailsWith<InvalidAlgorithmParameterException> {
      certPathValidator.validate(Chains.valid, params)
    }
    assertFailsWith<InvalidAlgorithmParameterException> {
      pkixCertPathValidator.validate(Chains.valid, params)
    }
  }

  @Test
  fun nullDate_throwsCertPathValidatorException() {
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(Chains.valid, PKIXParameters(setOf(testAnchor)))
      }
    val pkixException =
      assertFailsWith<CertPathValidatorException> {
        pkixCertPathValidator.validate(Chains.valid, PKIXParameters(setOf(testAnchor)))
      }
    assertThat(exception.reason).isEqualTo(BasicReason.EXPIRED)
    assertThat(pkixException.reason).isEqualTo(BasicReason.EXPIRED)
  }

  @Test
  fun validChain_returnsSuccess() {
    val certPath = Chains.valid
    val result = certPathValidator.validate(certPath, testParams) as PKIXCertPathValidatorResult
    assertThat(result.trustAnchor).isEqualTo(testAnchor)
    assertThat(result.policyTree).isNull()
    assertThat(result.publicKey).isEqualTo(certPath.certificates.first().publicKey)
  }

  @Test
  fun multipleAnchors_returnsSuccess() {
    val certPath = Chains.valid
    val params = PKIXParameters(setOf(prodAnchor, testAnchor)).apply { date = FakeCalendar.today() }
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
  fun wrongAnchor_throwsCertPathValidatorException() {
    val certPath = Chains.valid
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(certPath, prodParams)
      }
    val pkixException =
      assertFailsWith<CertPathValidatorException> {
        pkixCertPathValidator.validate(certPath, prodParams)
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
    assertThat(pkixException.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun multipleWrongAnchors_throwsCertPathValidatorException() {
    val params = PKIXParameters(setOf(prodAnchor, prodAnchor)).apply { date = FakeCalendar.today() }
    val exception =
      assertFailsWith<CertPathValidatorException> {
        certPathValidator.validate(Chains.valid, params)
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
  fun additionalCertPathChecker_isCalled() {
    assertFailsWith<FakeChecker.Exception> {
      certPathValidator.validate(
        Chains.valid,
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
