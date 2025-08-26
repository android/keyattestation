package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.protobuf.ByteString

/**
 * A [ChallengeChecker] that checks a list of [ChallengeChecker]s in order.
 *
 * Checks are ordered and halt after the first failure.
 */
class ChainedChallengeChecker(private val challengeCheckers: List<ChallengeChecker>) :
  ChallengeChecker {

  /**
   * Checks the given challenge for validity.
   *
   * @param challenge the challenge being checked
   * @return true if the challenge is valid, else false
   */
  override fun checkChallenge(challenge: ByteString): Boolean {
    // Manually loop instead of using .all() since we want to ensure order of checks and early
    // return on failure.
    for (challengeChecker in challengeCheckers) {
      if (!challengeChecker.checkChallenge(challenge)) {
        return false
      }
    }
    return true
  }

  companion object {
    /**
     * Creates a [ChainedChallengeChecker] with the given [ChallengeChecker]s.
     *
     * @param challengeCheckers the [ChallengeChecker]s to chain
     * @return a [ChainedChallengeChecker] with the given [ChallengeChecker]s
     */
    fun of(vararg challengeCheckers: ChallengeChecker): ChainedChallengeChecker {
      return ChainedChallengeChecker(challengeCheckers.toList())
    }
  }
}
