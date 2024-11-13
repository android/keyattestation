package com.android.keyattestation.verifier

import com.google.auto.value.AutoBuilder
import com.google.common.collect.ImmutableSet
import com.google.protobuf.ByteString

/** Builder for [AttestationApplicationId]. */
@AutoBuilder(ofClass = AttestationApplicationId::class)
abstract class AttestationApplicationIdBuilder {
  abstract fun setPackages(
    packages: MutableSet<AttestationPackageInfo>
  ): AttestationApplicationIdBuilder

  abstract fun setSignatures(signatures: Set<ByteString>): AttestationApplicationIdBuilder

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
