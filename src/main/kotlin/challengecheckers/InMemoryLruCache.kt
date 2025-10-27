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
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import com.google.errorprone.annotations.ThreadSafe
import com.google.protobuf.ByteString

/**
 * A [ChallengeChecker] which checks for replay of challenges via an in-memory LRU cache which holds
 * up to `maxCacheSize` challenges. Challenges are considered invalid if they are already present in
 * the cache, which prevents replay (reuse of challenges). Checking a challenge will affect the
 * ordering of the cache, making it more-recently-used.
 *
 * @property maxCacheSize the maximum number of challenges to cache
 */
@ThreadSafe
class InMemoryLruCache(private val maxCacheSize: Int) : ChallengeChecker {
  // Cache to store challenges. The value (Boolean) doesn't matter, only the presence of the key.
  private val cache: Cache<ByteString, Boolean> =
    CacheBuilder.newBuilder().maximumSize(maxCacheSize.toLong()).build()

  override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> {
    val mapView = cache.asMap()
    val isPresent = mapView.putIfAbsent(challenge, true)
    if (isPresent == null) {
      return Futures.immediateFuture(true)
    }
    return Futures.immediateFuture(false)
  }
}
