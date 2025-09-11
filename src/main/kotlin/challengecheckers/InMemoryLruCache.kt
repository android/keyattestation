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
import com.google.protobuf.ByteString

/**
 * A [ChallengeChecker] which checks for replay of challenges via an in-memory LRU cache which holds
 * up to `maxCacheSize` challenges. Challenges are considered invalid if they are already present in
 * the cache, which prevents replay (reuse of challenges). Checking a challenge will affect the
 * ordering of the cache, making it more-recently-used.
 *
 * @property maxCacheSize the maximum number of challenges to cache
 */
class InMemoryLruCache(private val maxCacheSize: Int) : ChallengeChecker {
  // Use a LinkedHashMap instead of LinkedHashSet even though we don't care about the values since
  // it can order entries by access-order. Use default initial capacity and load factor.
  private val cache: LinkedHashMap<ByteString, Int> =
    object : LinkedHashMap<ByteString, Int>(16, 0.75f, true) {

      // Used to query whether the oldest entry should be removed from the cache.
      override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteString, Int>) =
        size > maxCacheSize
    }

  override fun checkChallenge(challenge: ByteString): Boolean {
    val previousValue = cache.putIfAbsent(challenge, 1)
    return previousValue == null
  }
}
