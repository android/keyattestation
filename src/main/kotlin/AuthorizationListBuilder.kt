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

/** Builder for [AuthorizationList]. */
@AutoBuilder(ofClass = AuthorizationList::class)
abstract class AuthorizationListBuilder {
  abstract fun setPurposes(purpose: Set<BigInteger>): AuthorizationListBuilder

  abstract fun setAlgorithms(algorithm: BigInteger): AuthorizationListBuilder

  abstract fun setKeySize(keySize: BigInteger): AuthorizationListBuilder

  abstract fun setDigests(digests: Set<BigInteger>): AuthorizationListBuilder

  abstract fun setPaddings(paddings: Set<BigInteger>): AuthorizationListBuilder

  abstract fun setEcCurve(ecCurve: BigInteger): AuthorizationListBuilder

  abstract fun setRsaPublicExponent(rsaPublicExponent: BigInteger): AuthorizationListBuilder

  abstract fun setActiveDateTime(activeDateTime: BigInteger): AuthorizationListBuilder

  abstract fun setOriginationExpireDateTime(
    originationExpireDateTime: BigInteger
  ): AuthorizationListBuilder

  abstract fun setUsageExpireDateTime(usageExpireDateTime: BigInteger): AuthorizationListBuilder

  abstract fun setNoAuthRequired(noAuthRequired: Boolean): AuthorizationListBuilder

  abstract fun setUserAuthType(userAuthType: BigInteger): AuthorizationListBuilder

  abstract fun setTrustedUserPresenceRequired(
    trustedUserPresenceRequired: Boolean
  ): AuthorizationListBuilder

  abstract fun setUnlockedDeviceRequired(unlockedDeviceRequired: Boolean): AuthorizationListBuilder

  abstract fun setAuthTimeout(authTimeout: BigInteger): AuthorizationListBuilder

  abstract fun setCreationDateTime(creationDateTime: BigInteger): AuthorizationListBuilder

  abstract fun setOrigin(origin: BigInteger): AuthorizationListBuilder

  abstract fun setRollbackResistant(rollbackResistant: Boolean): AuthorizationListBuilder

  abstract fun setRootOfTrust(rootOfTrust: RootOfTrust): AuthorizationListBuilder

  abstract fun setOsVersion(osVersion: BigInteger): AuthorizationListBuilder

  abstract fun setOsPatchLevel(osPatchLevel: BigInteger): AuthorizationListBuilder

  abstract fun setAttestationApplicationId(
    attestationApplicationId: AttestationApplicationId
  ): AuthorizationListBuilder

  abstract fun setAttestationIdBrand(attestationIdBrand: String): AuthorizationListBuilder

  abstract fun setAttestationIdDevice(attestationIdDevice: String): AuthorizationListBuilder

  abstract fun setAttestationIdProduct(attestationIdProduct: String): AuthorizationListBuilder

  abstract fun setAttestationIdSerial(attestationIdSerial: String): AuthorizationListBuilder

  abstract fun setAttestationIdImei(attestationIdImei: String): AuthorizationListBuilder

  abstract fun setAttestationIdMeid(attestationIdMeid: String): AuthorizationListBuilder

  abstract fun setAttestationIdManufacturer(
    attestationIdManufacturer: String
  ): AuthorizationListBuilder

  abstract fun setAttestationIdModel(attestationIdModel: String): AuthorizationListBuilder

  abstract fun setVendorPatchLevel(vendorPatchLevel: BigInteger): AuthorizationListBuilder

  abstract fun setBootPatchLevel(bootPatchLevel: BigInteger): AuthorizationListBuilder

  abstract fun setAttestationIdSecondImei(attestationIdSecondImei: String): AuthorizationListBuilder

  abstract fun setModuleHash(moduleHash: String): AuthorizationListBuilder

  abstract fun build(): AuthorizationList

  companion object {
    @JvmStatic
    fun authorizationListBuilder(): AuthorizationListBuilder =
      AutoBuilder_AuthorizationListBuilder()

    @JvmStatic
    fun authorizationListBuilder(authorizationList: AuthorizationList): AuthorizationListBuilder =
      AutoBuilder_AuthorizationListBuilder(authorizationList)
  }
}
