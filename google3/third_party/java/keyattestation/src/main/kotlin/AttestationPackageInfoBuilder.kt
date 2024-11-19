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
import java.math.BigInteger

/** Builder for [AttestationPackageInfo]. */
@AutoBuilder(ofClass = AttestationPackageInfo::class)
abstract class AttestationPackageInfoBuilder {
  abstract fun setName(name: String): AttestationPackageInfoBuilder

  abstract fun setVersion(version: BigInteger): AttestationPackageInfoBuilder

  abstract fun build(): AttestationPackageInfo

  companion object {
    @JvmStatic
    fun attestationPackageInfoBuilder(): AttestationPackageInfoBuilder =
      AutoBuilder_AttestationPackageInfoBuilder()

    @JvmStatic
    fun attestationPackageInfoBuilder(
      attestationPackageInfo: AttestationPackageInfo
    ): AttestationPackageInfoBuilder =
      AutoBuilder_AttestationPackageInfoBuilder(attestationPackageInfo)
  }
}
