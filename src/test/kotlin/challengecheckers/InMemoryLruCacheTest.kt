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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class InMemoryLruCacheTest {

  @Test
  fun checkChallenge_firstChallenge_returnsTrue() {
    val challengeChecker = InMemoryLruCache(1)
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge"))).isTrue()
  }

  @Test
  fun checkChallenge_partialCacheCheckNewChallenge_returnsTrue() {
    val challengeChecker = InMemoryLruCache(10)
    for (i in 1..9) {
      assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge$i"))).isTrue()
    }

    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("foo"))).isTrue()
  }

  @Test
  fun checkChallenge_fullCacheCheckExistingChallenge_returnsFalse() {
    val challengeChecker = InMemoryLruCache(10)
    for (i in 1..10) {
      assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge$i"))).isTrue()
    }

    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge1"))).isFalse()
  }

  @Test
  fun checkChallenge_overflowCacheCheckOldestChallenge_returnsTrue() {
    val challengeChecker = InMemoryLruCache(10)

    // Fill cache with 10 challenges and overflow with the 11th challenge.
    for (i in 1..11) {
      assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge$i"))).isTrue()
    }

    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge1"))).isTrue()
  }

  @Test
  fun checkChallenge_overflowCacheCheckNewerChallenge_returnsFalse() {
    val challengeChecker = InMemoryLruCache(10)
    for (i in 1..11) {
      assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge$i"))).isTrue()
    }

    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge2"))).isFalse()
  }

  @Test
  fun checkChallenge_checkingChallenge_affectsCacheOrder() {
    // fill cache
    val challengeChecker = InMemoryLruCache(3)
    for (i in 1..3) {
      assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge$i"))).isTrue()
    }

    // check oldest challenge
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge1"))).isFalse()

    // add new challenge to overflow cache + kick out least-recently-used challenge
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge4"))).isTrue()

    // check that challenge1 is still in the cache + challenge2 is kicked out
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge1"))).isFalse()
    assertThat(challengeChecker.checkChallenge(ByteString.copyFromUtf8("challenge2"))).isTrue()
  }
}
