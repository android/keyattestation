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
import com.android.keyattestation.verifier.testing.TestUtils.falseChecker
import com.android.keyattestation.verifier.testing.TestUtils.trueChecker
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
