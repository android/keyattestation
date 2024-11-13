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
