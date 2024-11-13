package com.android.keyattestation.verifier

import com.google.auto.value.AutoBuilder
import com.google.protobuf.ByteString
import java.math.BigInteger

/** Builder for [KeyDescription]. */
@AutoBuilder(ofClass = KeyDescription::class)
abstract class KeyDescriptionBuilder {
  abstract fun setAttestationVersion(attestationVersion: BigInteger): KeyDescriptionBuilder

  abstract fun setAttestationSecurityLevel(
    attestationSecurityLevel: SecurityLevel
  ): KeyDescriptionBuilder

  abstract fun setKeymasterVersion(keymasterVersion: BigInteger): KeyDescriptionBuilder

  abstract fun setKeymasterSecurityLevel(
    keymasterSecurityLevel: SecurityLevel
  ): KeyDescriptionBuilder

  abstract fun setAttestationChallenge(attestationChallenge: ByteString): KeyDescriptionBuilder

  abstract fun setUniqueId(uniqueId: ByteString): KeyDescriptionBuilder

  abstract fun setSoftwareEnforced(softwareEnforced: AuthorizationList): KeyDescriptionBuilder

  abstract fun setTeeEnforced(teeEnforced: AuthorizationList): KeyDescriptionBuilder

  abstract fun build(): KeyDescription

  companion object {
    @JvmStatic
    fun keyDescriptionBuilder(): KeyDescriptionBuilder = AutoBuilder_KeyDescriptionBuilder()

    @JvmStatic
    fun keyDescriptionBuilder(keyDescription: KeyDescription): KeyDescriptionBuilder =
      AutoBuilder_KeyDescriptionBuilder(keyDescription)
  }
}
