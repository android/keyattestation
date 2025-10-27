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
import com.google.common.collect.ImmutableList
import com.google.common.truth.Truth.assertThat
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import com.google.errorprone.annotations.ThreadSafe
import com.google.protobuf.ByteString
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.guava.await
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@ThreadSafe
private class TestChallengeChecker(private val result: Boolean) : ChallengeChecker {
  val wasCalled = AtomicBoolean(false)

  override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> {
    wasCalled.set(true)
    return Futures.immediateFuture(result)
  }
}

@RunWith(JUnit4::class)
class ChainedChallengeCheckerTest {
  companion object {
    private val testChallenge = ByteString.copyFromUtf8("challenge")
  }

  @Test
  fun checkChallenge_emptyCheckers_returnsTrue() = runBlocking {
    val challengeChecker = ChainedChallengeChecker.of(this)
    assertThat(challengeChecker.checkChallenge(testChallenge).await()).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersTrue_returnsTrue() = runBlocking {
    val challengeChecker =
      ChainedChallengeChecker.of(this, ChallengeMatcher(testChallenge), InMemoryLruCache(10))
    assertThat(challengeChecker.checkChallenge(testChallenge).await()).isTrue()
  }

  @Test
  fun checkChallenge_allCheckersFalse_returnsFalse() = runBlocking {
    val challengeCheckers: MutableList<ChallengeChecker> = mutableListOf()
    for (i in 1..10) {
      challengeCheckers.add(falseChecker)
    }
    val challengeChecker = ChainedChallengeChecker(ImmutableList.copyOf(challengeCheckers), this)

    assertThat(challengeChecker.checkChallenge(testChallenge).await()).isFalse()
  }

  @Test
  fun checkChallenge_lastCheckerFalse_returnsFalse() = runBlocking {
    val challengeCheckers: MutableList<ChallengeChecker> = mutableListOf()
    for (i in 1..10) {
      challengeCheckers.add(trueChecker)
    }
    challengeCheckers.add(falseChecker)
    val challengeChecker = ChainedChallengeChecker(ImmutableList.copyOf(challengeCheckers), this)

    assertThat(challengeChecker.checkChallenge(testChallenge).await()).isFalse()
  }

  @Test
  fun checkChallenge_firstCheckerFalse_returnsFalseAndStopsEarly() = runBlocking {
    val checker2 = TestChallengeChecker(true)
    val checker3 = TestChallengeChecker(true)
    val challengeChecker = ChainedChallengeChecker.of(this, falseChecker, checker2, checker3)

    assertThat(challengeChecker.checkChallenge(testChallenge).await()).isFalse()
    assertThat(checker2.wasCalled.get()).isFalse()
    assertThat(checker3.wasCalled.get()).isFalse()
  }
}
