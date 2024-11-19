/*
 * Copyright 2024 Google LLC
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

import com.google.auto.value.AutoBuilder
import com.google.protobuf.ByteString

/** Builder for [RootOfTrust]. */
@AutoBuilder(ofClass = RootOfTrust::class)
abstract class RootOfTrustBuilder {

  abstract fun setVerifiedBootKey(verifiedBootKey: ByteString): RootOfTrustBuilder

  abstract fun setDeviceLocked(deviceLocked: Boolean): RootOfTrustBuilder

  abstract fun setVerifiedBootState(verifiedBootState: VerifiedBootState): RootOfTrustBuilder

  abstract fun setVerifiedBootHash(verifiedBootHash: ByteString): RootOfTrustBuilder

  abstract fun build(): RootOfTrust

  companion object {
    @JvmStatic
    fun rootOfTrustBuilder(): RootOfTrustBuilder {
      return AutoBuilder_RootOfTrustBuilder()
    }

    @JvmStatic
    fun rootOfTrustBuilder(rootOfTrust: RootOfTrust): RootOfTrustBuilder {
      return AutoBuilder_RootOfTrustBuilder(rootOfTrust)
    }
  }
}
