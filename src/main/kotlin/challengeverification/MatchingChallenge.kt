package com.android.keyattestation.verifier.challengeverification

import com.google.protobuf.ByteString

/**
 * A basic implementation of [ChallengeChecker] that checks if the challenge in the attestation
 * certificate matches the expected challenge.
 */
class MatchingChallenge(private val expectedChallenge: ByteString) : ChallengeChecker {

  override fun checkChallenge(challenge: ByteString): Boolean = challenge.equals(expectedChallenge)
}
