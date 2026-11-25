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
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import com.google.protobuf.ByteString

/**
 * These ChallengeCheckers are intentionally insecure and should only be used in tests.
 *
 * If you're using these in production, you have a security hole.
 */
object InsecureCheckers {
  /** Returns false for all challenges. */
  @JvmField
  val FalseChecker =
    object : ChallengeChecker {
      override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> =
        Futures.immediateFuture(false)
    }

  /** Returns true for all challenges. */
  @JvmField
  val TrueChecker =
    object : ChallengeChecker {
      override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> =
        Futures.immediateFuture(true)
    }
}
