package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.protobuf.ByteString

/** A [ChallengeChecker] that checks a list of [ChallengeChecker]s in order. */
class ChainedChallengeChecker : ChallengeChecker {

  private val challengeCheckers: MutableList<ChallengeChecker> = mutableListOf()

  /**
   * Adds a [ChallengeChecker] to the chain.
   *
   * @param challengeChecker The [ChallengeChecker] to add to the chain.
   */
  fun addChallengeChecker(challengeChecker: ChallengeChecker) {
    challengeCheckers.add(challengeChecker)
  }

  /**
   * Checks the given challenge for validity.
   *
   * @param challenge The challenge being check.
   * @return True if the challenge is valid, else false.
   */
  override fun checkChallenge(challenge: ByteString): Boolean {
    for (challengeChecker in challengeCheckers) {
      if (!challengeChecker.checkChallenge(challenge)) {
        return false
      }
    }
    return true
  }
}
