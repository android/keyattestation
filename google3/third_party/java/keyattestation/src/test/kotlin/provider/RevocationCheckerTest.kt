package com.android.keyattestation.verifier.provider

import com.android.keyattestation.verifier.testing.Certs
import com.android.keyattestation.verifier.testing.Chains
import com.android.keyattestation.verifier.testing.FakeCalendar
import java.security.Security
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXParameters
import kotlin.test.assertFailsWith
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class RevocationCheckerTest {
  private val params =
    PKIXParameters(setOf(Certs.rootAnchor)).apply {
      isRevocationEnabled = false
      date = FakeCalendar.today()
    }
  private val revocationChecker =
    RevocationChecker(setOf(Chains.REVOKED_SERIAL_NUMBER.toString(16)))
  private val validator = CertPathValidator.getInstance("KeyAttestation")
  private val pkixValidator = CertPathValidator.getInstance("PKIX")

  @Test
  fun withoutRevocationChecker_validationSucceeds() {
    validator.validate(Chains.revoked, params)
    pkixValidator.validate(Chains.revoked, params)
  }

  @Test
  fun withRevocationChecker_throwsCertPathValidatorException() {
    assertFailsWith<CertPathValidatorException> {
      validator.validate(Chains.revoked, params.apply { addCertPathChecker(revocationChecker) })
    }
    assertFailsWith<CertPathValidatorException> {
      pkixValidator.validate(Chains.revoked, params.apply { addCertPathChecker(revocationChecker) })
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
