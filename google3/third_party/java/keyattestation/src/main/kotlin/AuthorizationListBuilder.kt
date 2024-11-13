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
