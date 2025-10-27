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

package com.android.keyattestation.verifier

import com.google.common.util.concurrent.ListenableFuture
import com.google.errorprone.annotations.ThreadSafe
import com.google.protobuf.ByteString

/**
 * An interface to handle checking validity of challenges.
 *
 * Implementations of this interface must be thread-safe. Multiple threads may call [checkChallenge]
 * on the same instance concurrently.
 */
@ThreadSafe
interface ChallengeChecker {
  /**
   * Checks the given [challenge] for validity.
   *
   * @return A ListenableFuture containing True if the challenge is valid, else false.
   */
  fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean>
}
