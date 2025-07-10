package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.VerificationResult
import com.android.keyattestation.verifier.Verifier
import com.android.keyattestation.verifier.testing.TestUtils.prodRoot
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.TrustAnchor
import java.time.Instant
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ChallengeMatcherTest {

  @Test
  fun checkChallenge_matchingChallenge_returnsTrue() {
    val challengeChecker = ChallengeMatcher(ByteString.copyFromUtf8("challenge"))
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge"))).isTrue()
  }

  @Test
  fun checkChallenge_mismatchedChallenge_returnsFalse() {
    val challengeChecker = ChallengeMatcher(ByteString.copyFromUtf8("challenge"))
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("foo"))).isFalse()
  }

  @Test
  fun verify_expectedChallenge_returnsSuccess() {
    val verifier =
      Verifier(
        { setOf(TrustAnchor(prodRoot, /* nameConstraints= */ null)) },
        { setOf<String>() },
        { Instant.now() },
      )
    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(
      verifier.verify(chain, ChallengeMatcher(ByteString.copyFromUtf8("challenge")))
    )
  }

  @Test
  fun verify_unexpectedChallenge_returnsChallengeMismatch() {
    val verifier =
      Verifier(
        { setOf(TrustAnchor(prodRoot, /* nameConstraints= */ null)) },
        { setOf<String>() },
        { Instant.now() },
      )
    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.ChallengeMismatch>(
      verifier.verify(chain, ChallengeMatcher(ByteString.copyFromUtf8("foo")))
    )
  }
}
