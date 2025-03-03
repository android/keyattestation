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
import com.google.common.collect.ImmutableSet
import com.google.common.collect.toImmutableSet
import com.google.protobuf.ByteString

/** Builder for [AttestationApplicationId]. */
@AutoBuilder(ofClass = AttestationApplicationId::class)
abstract class AttestationApplicationIdBuilder {
  abstract fun setPackages(
    packages: ImmutableSet<AttestationPackageInfo>
  ): AttestationApplicationIdBuilder

  fun setPackages(packages: Set<AttestationPackageInfo>): AttestationApplicationIdBuilder =
    setPackages(packages.toImmutableSet())

  abstract fun setSignatures(signatures: ImmutableSet<ByteString>): AttestationApplicationIdBuilder

  fun setSignatures(signatures: Set<ByteString>): AttestationApplicationIdBuilder =
    setSignatures(signatures.toImmutableSet())

  abstract fun build(): AttestationApplicationId

  companion object {
    @JvmStatic
    fun attestationApplicationIdBuilder(): AttestationApplicationIdBuilder =
      AutoBuilder_AttestationApplicationIdBuilder()
        .setPackages(ImmutableSet.of())
        .setSignatures(ImmutableSet.of())

    @JvmStatic
    fun attestationApplicationIdBuilder(
      attestationApplicationId: AttestationApplicationId
    ): AttestationApplicationIdBuilder =
      AutoBuilder_AttestationApplicationIdBuilder(attestationApplicationId)
  }
}
