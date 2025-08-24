package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ChainedChallengeCheckerTest {
  companion object {
    private val testChallenge = ByteString.copyFromUtf8("challenge")
    private val falseChecker =
      object : ChallengeChecker {
        override fun checkChallenge(challenge: ByteString): Boolean = false
      }
    private val trueChecker =
      object : ChallengeChecker {
        override fun checkChallenge(challenge: ByteString): Boolean = true
      }
  }

  @Test
  fun checkChallenge_emptyCheckers_returnsTrue() {
    val challengeChecker = ChainedChallengeChecker()
    assertThat(challengeChecker.checkChallenge(testChallenge)).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersTrue_returnsTrue() {
    val challengeChecker =
      ChainedChallengeChecker().apply {
        addChallengeChecker(ChallengeMatcher(testChallenge))
        addChallengeChecker(InMemoryLruCache(10))
      }
    assertThat(challengeChecker.checkChallenge(testChallenge)).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersFalse_returnsFalse() {
    val challengeChecker = ChainedChallengeChecker()
    for (i in 1..10) {
      challengeChecker.addChallengeChecker(falseChecker)
    }

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
  }

  @Test
  fun checkChallenge_lastCheckerFalse_returnsFalse() {
    val challengeChecker = ChainedChallengeChecker()
    for (i in 1..10) {
      challengeChecker.addChallengeChecker(trueChecker)
    }
    challengeChecker.addChallengeChecker(falseChecker)

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
  }

  @Test
  fun checkChallenge_firstCheckerFalse_returnsFalseAndStopsEarly() {
    var checker2Called = false
    var checker3Called = false
    val challengeChecker =
      ChainedChallengeChecker().apply {
        addChallengeChecker(falseChecker)
        addChallengeChecker(
          object : ChallengeChecker {
            override fun checkChallenge(challenge: ByteString): Boolean {
              checker2Called = true
              return true
            }
          }
        )
        addChallengeChecker(
          object : ChallengeChecker {
            override fun checkChallenge(challenge: ByteString): Boolean {
              checker3Called = true
              return true
            }
          }
        )
      }

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
    assertThat(checker2Called).isFalse()
    assertThat(checker3Called).isFalse()
  }
}
