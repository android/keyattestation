/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.common.collect.ImmutableList
import com.google.common.util.concurrent.ListenableFuture
import com.google.errorprone.annotations.ThreadSafe
import com.google.protobuf.ByteString
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.guava.await
import kotlinx.coroutines.guava.future

/**
 * A [ChallengeChecker] that checks a list of [ChallengeChecker]s in order. The [challengeCheckers]
 * will be executed in the provided [coroutineScope].
 *
 * Checks are ordered and halt after the first failure.
 */
@ThreadSafe
class ChainedChallengeChecker(
  private val challengeCheckers: ImmutableList<ChallengeChecker>,
  private val coroutineScope: CoroutineScope,
) : ChallengeChecker {

  override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> {
    return coroutineScope.future { checkChallengeSuspend(challenge) }
  }

  private suspend fun checkChallengeSuspend(challenge: ByteString): Boolean {
    // Manually loop instead of using .all() since we want to ensure order of checks and early
    // return on failure.
    for (challengeChecker in challengeCheckers) {
      val checkResult = challengeChecker.checkChallenge(challenge).await()
      if (!checkResult) {
        return false
      }
    }
    return true
  }

  companion object {
    /**
     * Creates a [ChainedChallengeChecker] with the given [ChallengeChecker]s. The
     * [challengeCheckers] will be executed in the provided [coroutineScope].
     */
    fun of(
      coroutineScope: CoroutineScope,
      vararg challengeCheckers: ChallengeChecker,
    ): ChainedChallengeChecker {
      return ChainedChallengeChecker(ImmutableList.copyOf(challengeCheckers), coroutineScope)
    }
  }
}
