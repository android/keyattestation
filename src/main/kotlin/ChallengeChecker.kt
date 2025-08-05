package com.android.keyattestation.verifier

import com.google.protobuf.ByteString

/** An interface to handle checking validity of challenges. */
interface ChallengeChecker {
  /**
   * Checks the given challenge for validity.
   *
   * @param challenge The challenge being check.
   * @return True if the challenge is valid, else false.
   */
  fun checkChallenge(challenge: ByteString): Boolean
}
