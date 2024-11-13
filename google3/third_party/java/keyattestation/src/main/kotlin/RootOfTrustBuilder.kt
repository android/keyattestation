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
