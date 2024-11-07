package com.android.keyattestation.verifier

import com.android.keyattestation.verifier.testing.CertLists
import com.android.keyattestation.verifier.testing.TestUtils.prodRoot
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.TrustAnchor
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

/** Unit tests for [Verifier]. */
@RunWith(JUnit4::class)
class VerifierTest {
  private val verifier = Verifier(setOf(TrustAnchor(prodRoot, /* nameConstraints= */ null)))

  @Test
  fun verify_validChain_returnsSuccess() {
    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    val result =
      assertIs<VerificationResult.Success>(verifier.verify(chain, "challenge".toByteArray()))
    assertThat(result.publicKey).isEqualTo(chain.leafCert().publicKey)
    assertThat(result.challenge).isEqualTo(ByteString.copyFromUtf8("challenge"))
    assertThat(result.securityLevel).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT)
    assertThat(result.verifiedBootState).isEqualTo(VerifiedBootState.UNVERIFIED)
  }

  @Test
  fun verify_unexpectedChallenge_returnsChallengeMismatch() {
    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.ChallengeMismatch>(verifier.verify(chain, "foo".toByteArray()))
  }

  @Test
  fun verify_unexpectedRootKey_returnsPathValidationFailure() {
    assertIs<VerificationResult.PathValidationFailure>(
      verifier.verify(CertLists.wrongTrustAnchor, "challenge".toByteArray())
    )
  }
}
