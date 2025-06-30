package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.protobuf.ByteString

/**
 * A basic implementation of [ChallengeChecker] that checks if the challenge in the attestation
 * certificate is equal to the expected challenge.
 */
class ChallengeMatcher(private val expectedChallenge: ByteString) : ChallengeChecker {

  constructor(expectedChallenge: ByteArray) : this(ByteString.copyFrom(expectedChallenge))

  override fun checkChallenge(challenge: ByteString): Boolean = challenge.equals(expectedChallenge)
}
