package com.android.keyattestation.verifier.challengecheckers

import com.android.keyattestation.verifier.ChallengeChecker
import com.google.protobuf.ByteString

/**
 * A [ChallengeChecker] which checks for replay of challenges via an in-memory LRU cache which holds
 * up to maxEntries challenges. Checking a challenge will affect the ordering of the cache, making
 * it more-recently-used.
 *
 * @property maxCacheSize the maximum number of challenges to cache.
 */
class InMemoryLruCache(private val maxCacheSize: Int) : ChallengeChecker {
  // Use a Map even though we don't care about the values to get average-case O(1) lookup,
  // insertion, and deletion. Use a LinkedHashMap to maintain a FIFO ordering of the cache.
  private val cache: LinkedHashMap<ByteString, Int> =
    object : LinkedHashMap<ByteString, Int>(maxCacheSize, 0.75f, true) {
      override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ByteString, Int>): Boolean {
        return size > maxCacheSize
      }
    }

  override fun checkChallenge(challenge: ByteString): Boolean {
    return cache.putIfAbsent(challenge, 1) == null
  }
}
