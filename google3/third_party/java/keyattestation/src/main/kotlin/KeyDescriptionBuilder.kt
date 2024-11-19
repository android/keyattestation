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
