package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

private class TestChallengeChecker(private val result: Boolean) : ChallengeChecker {
  var wasCalled = false

  override fun checkChallenge(challenge: ByteString): Boolean {
    wasCalled = true
    return result
  }
}

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
    val challengeChecker = ChainedChallengeChecker.of()
    assertThat(challengeChecker.checkChallenge(testChallenge)).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersTrue_returnsTrue() {
    val challengeChecker =
      ChainedChallengeChecker.of(ChallengeMatcher(testChallenge), InMemoryLruCache(10))
    assertThat(challengeChecker.checkChallenge(testChallenge)).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersFalse_returnsFalse() {
    val challengeCheckers: MutableList<ChallengeChecker> = mutableListOf()
    for (i in 1..10) {
      challengeCheckers.add(falseChecker)
    }
    val challengeChecker = ChainedChallengeChecker(challengeCheckers)

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
  }

  @Test
  fun checkChallenge_lastCheckerFalse_returnsFalse() {
    val challengeCheckers: MutableList<ChallengeChecker> = mutableListOf()
    for (i in 1..10) {
      challengeCheckers.add(trueChecker)
    }
    challengeCheckers.add(falseChecker)
    val challengeChecker = ChainedChallengeChecker(challengeCheckers)

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
  }

  @Test
  fun checkChallenge_firstCheckerFalse_returnsFalseAndStopsEarly() {
    val checker2 = TestChallengeChecker(true)
    val checker3 = TestChallengeChecker(true)
    val challengeChecker = ChainedChallengeChecker.of(falseChecker, checker2, checker3)

    assertThat(challengeChecker.checkChallenge(testChallenge)).isFalse()
    assertThat(checker2.wasCalled).isFalse()
    assertThat(checker3.wasCalled).isFalse()
  }
}
