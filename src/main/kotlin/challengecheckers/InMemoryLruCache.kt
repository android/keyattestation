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
