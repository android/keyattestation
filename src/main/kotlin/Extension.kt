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

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.Special
import co.nstant.`in`.cbor.model.SpecialType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.google.errorprone.annotations.Immutable
import com.google.protobuf.ByteString
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.cert.X509Certificate
import java.time.YearMonth
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import kotlin.text.Charsets.UTF_8
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension

@Immutable
data class ProvisioningInfoMap(
  val certificatesIssued: Int,
) {
  fun cborEncode(): ByteArray {
    val map = Map()
    map.put(UnsignedInteger(1L), certificatesIssued.asDataItem())
    return cborEncode(map)
  }

  fun encodeToAsn1(): ByteArray = DEROctetString(cborEncode()).encoded

  companion object {
    /* OID for the provisioning info map extension.
     * https://developer.android.com/privacy-and-security/security-key-attestation#provisioning_attestation_ext_schema
     */
    @JvmField val OID = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")

    @JvmStatic
    fun parseFrom(cert: X509Certificate) = cert.getExtensionValue(OID.id)?.let { parseFrom(it) }

    @JvmStatic
    fun parseFrom(bytes: ByteArray?) =
      try {
        val cborBytes = ASN1OctetString.getInstance(bytes).octets
        from(cborDecode(cborBytes).asMap())
      } catch (e: CborException) {
        throw IllegalArgumentException(e)
      }

    private fun from(seq: Map): ProvisioningInfoMap {
      require(seq.keys.size >= 1)
      return ProvisioningInfoMap(
        certificatesIssued = seq.get(UnsignedInteger(1L)).asInteger(),
      )
    }
  }
}

data class DeviceIdentity(
  val brand: String?,
  val device: String?,
  val product: String?,
  val serialNumber: String?,
  val imeis: Set<String>,
  val meid: String?,
  val manufacturer: String?,
  val model: String?,
) {
  companion object {
    @JvmStatic
    fun parseFrom(description: KeyDescription) =
      DeviceIdentity(
        description.hardwareEnforced.attestationIdBrand,
        description.hardwareEnforced.attestationIdDevice,
        description.hardwareEnforced.attestationIdProduct,
        description.hardwareEnforced.attestationIdSerial,
        setOfNotNull(
          description.hardwareEnforced.attestationIdImei,
          description.hardwareEnforced.attestationIdSecondImei,
        ),
        description.hardwareEnforced.attestationIdMeid,
        description.hardwareEnforced.attestationIdManufacturer,
        description.hardwareEnforced.attestationIdModel,
      )
  }
}

@Immutable
data class KeyDescription(
  val attestationVersion: BigInteger,
  val attestationSecurityLevel: SecurityLevel,
  val keyMintVersion: BigInteger,
  val keyMintSecurityLevel: SecurityLevel,
  val attestationChallenge: ByteString,
  val uniqueId: ByteString,
  val softwareEnforced: AuthorizationList,
  val hardwareEnforced: AuthorizationList,
) {
  fun asExtension(): Extension {
    return Extension(OID, /* critical= */ false, encodeToAsn1())
  }

  fun encodeToAsn1(): ByteArray =
    buildList {
        add(attestationVersion.toAsn1())
        add(attestationSecurityLevel.toAsn1())
        add(keyMintVersion.toAsn1())
        add(keyMintSecurityLevel.toAsn1())
        add(attestationChallenge.toAsn1())
        add(uniqueId.toAsn1())
        add(softwareEnforced.toAsn1())
        add(hardwareEnforced.toAsn1())
      }
      .let { DERSequence(it.toTypedArray()).encoded }

  companion object {
    /* OID for the key attestation extension.
     * https://source.android.com/docs/security/features/keystore/attestation#schema
     */
    @JvmField val OID = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

    @JvmStatic
    fun parseFrom(cert: X509Certificate) =
      cert
        .getExtensionValue(OID.id)
        .let { ASN1OctetString.getInstance(it).octets }
        .let { parseFrom(it) }

    @JvmStatic
    fun parseFrom(bytes: ByteArray) =
      try {
        from(ASN1Sequence.getInstance(bytes))
      } catch (e: NullPointerException) {
        // Workaround for a NPE in BouncyCastle.
        // https://github.com/bcgit/bc-java/blob/228211ecb973fe87fdd0fc4ab16ba0446ec1a29c/core/src/main/java/org/bouncycastle/asn1/ASN1UniversalType.java#L24
        throw IllegalArgumentException(e)
      }

    private fun from(seq: ASN1Sequence): KeyDescription {
      require(seq.size() == 8)
      return KeyDescription(
        attestationVersion = seq.getObjectAt(0).toInt(),
        attestationSecurityLevel = seq.getObjectAt(1).toSecurityLevel(),
        keyMintVersion = seq.getObjectAt(2).toInt(),
        keyMintSecurityLevel = seq.getObjectAt(3).toSecurityLevel(),
        attestationChallenge = seq.getObjectAt(4).toByteString(),
        uniqueId = seq.getObjectAt(5).toByteString(),
        softwareEnforced = seq.getObjectAt(6).toAuthorizationList(),
        hardwareEnforced = seq.getObjectAt(7).toAuthorizationList(),
      )
    }
  }
}

/**
 * Representation of the SecurityLevel enum contained within [KeyDescription].
 *
 * @see https://source.android.com/docs/security/features/keystore/attestation#securitylevel-values
 */
enum class SecurityLevel(val value: Int) {
  SOFTWARE(0),
  TRUSTED_ENVIRONMENT(1),
  STRONG_BOX(2);

  internal fun toAsn1() = ASN1Enumerated(value)
}

/**
 * Representation of the Origin enum contained within [KeyDescription].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl
 */
enum class Origin(val value: Long) {
  GENERATED(0),
  DERIVED(1),
  IMPORTED(2),
  RESERVED(3),
  SECURELY_IMPORTED(4);

  internal fun toAsn1() = ASN1Integer(value)
}

/**
 * KeyMint tag names and IDs.
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
 */
enum class KeyMintTag(val value: Int) {
  PURPOSE(1),
  ALGORITHM(2),
  KEY_SIZE(3),
  DIGEST(5),
  PADDING(6),
  EC_CURVE(10),
  RSA_PUBLIC_EXPONENT(200),
  ACTIVE_DATE_TIME(400),
  ORIGINATION_EXPIRE_DATE_TIME(401),
  USAGE_EXPIRE_DATE_TIME(402),
  NO_AUTH_REQUIRED(503),
  USER_AUTH_TYPE(504),
  AUTH_TIMEOUT(505),
  ALLOW_WHILE_ON_BODY(506),
  TRUSTED_USER_PRESENCE_REQUIRED(507),
  UNLOCKED_DEVICE_REQUIRED(509),
  CREATION_DATE_TIME(701),
  ORIGIN(702),
  ROLLBACK_RESISTANT(703),
  ROOT_OF_TRUST(704),
  OS_VERSION(705),
  OS_PATCH_LEVEL(706),
  ATTESTATION_APPLICATION_ID(709),
  ATTESTATION_ID_BRAND(710),
  ATTESTATION_ID_DEVICE(711),
  ATTESTATION_ID_PRODUCT(712),
  ATTESTATION_ID_SERIAL(713),
  ATTESTATION_ID_IMEI(714),
  ATTESTATION_ID_MEID(715),
  ATTESTATION_ID_MANUFACTURER(716),
  ATTESTATION_ID_MODEL(717),
  VENDOR_PATCH_LEVEL(718),
  BOOT_PATCH_LEVEL(719),
  ATTESTATION_ID_SECOND_IMEI(723),
  MODULE_HASH(724);

  companion object {
    fun from(value: Int) =
      values().firstOrNull { it.value == value }
        ?: throw IllegalArgumentException("unknown tag number: $value")
  }
}

/**
 * Representation of the AuthorizationList sequence contained within [KeyDescription].
 *
 * @see
 *   https://source.android.com/docs/security/features/keystore/attestation#authorizationlist-fields
 */
@Immutable
data class AuthorizationList(
  @SuppressWarnings("Immutable") val purposes: Set<BigInteger>? = null,
  val keySize: BigInteger? = null,
  val algorithms: BigInteger? = null,
  @SuppressWarnings("Immutable") val digests: Set<BigInteger>? = null,
  @SuppressWarnings("Immutable") val paddings: Set<BigInteger>? = null,
  val ecCurve: BigInteger? = null,
  val rsaPublicExponent: BigInteger? = null,
  val activeDateTime: BigInteger? = null,
  val originationExpireDateTime: BigInteger? = null,
  val usageExpireDateTime: BigInteger? = null,
  val noAuthRequired: Boolean? = null,
  val userAuthType: BigInteger? = null,
  val authTimeout: BigInteger? = null,
  val trustedUserPresenceRequired: Boolean? = null,
  val unlockedDeviceRequired: Boolean? = null,
  val creationDateTime: BigInteger? = null,
  val origin: Origin? = null,
  val rollbackResistant: Boolean? = null,
  val rootOfTrust: RootOfTrust? = null,
  val osVersion: BigInteger? = null,
  val osPatchLevel: PatchLevel? = null,
  val attestationApplicationId: AttestationApplicationId? = null,
  val attestationIdBrand: String? = null,
  val attestationIdDevice: String? = null,
  val attestationIdProduct: String? = null,
  val attestationIdSerial: String? = null,
  val attestationIdImei: String? = null,
  val attestationIdMeid: String? = null,
  val attestationIdManufacturer: String? = null,
  val attestationIdModel: String? = null,
  val vendorPatchLevel: PatchLevel? = null,
  val bootPatchLevel: PatchLevel? = null,
  val attestationIdSecondImei: String? = null,
  val moduleHash: ByteString? = null,
) {
  /**
   * Converts the representation of an [AuthorizationList] to an ASN.1 sequence.
   *
   * Properties that are null are not included in the sequence.
   */
  internal fun toAsn1() =
    buildList {
        purposes?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.PURPOSE)) }
        algorithms?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ALGORITHM)) }
        keySize?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.KEY_SIZE)) }
        digests?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.DIGEST)) }
        paddings?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.PADDING)) }
        ecCurve?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.EC_CURVE)) }
        rsaPublicExponent?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.RSA_PUBLIC_EXPONENT)) }
        activeDateTime?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ACTIVE_DATE_TIME)) }
        originationExpireDateTime?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ORIGINATION_EXPIRE_DATE_TIME))
        }
        usageExpireDateTime?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.USAGE_EXPIRE_DATE_TIME))
        }
        if (noAuthRequired != null) {
          check(noAuthRequired) { "noAuthRequired must be null or true" }
          add(DERNull.INSTANCE.toTaggedObject(KeyMintTag.NO_AUTH_REQUIRED))
        }
        userAuthType?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.USER_AUTH_TYPE)) }
        authTimeout?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.AUTH_TIMEOUT)) }
        if (trustedUserPresenceRequired != null) {
          check(trustedUserPresenceRequired) { "trustedUserPresenceRequired must be null or true" }
          add(DERNull.INSTANCE.toTaggedObject(KeyMintTag.TRUSTED_USER_PRESENCE_REQUIRED))
        }
        if (unlockedDeviceRequired != null) {
          check(unlockedDeviceRequired) { "unlockedDeviceRequired must be null or true" }
          add(DERNull.INSTANCE.toTaggedObject(KeyMintTag.UNLOCKED_DEVICE_REQUIRED))
        }
        creationDateTime?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.CREATION_DATE_TIME)) }
        origin?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ORIGIN)) }
        if (rollbackResistant != null) {
          check(rollbackResistant) { "rollbackResistant must be null or true" }
          add(DERNull.INSTANCE.toTaggedObject(KeyMintTag.ROLLBACK_RESISTANT))
        }
        rootOfTrust?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ROOT_OF_TRUST)) }
        osVersion?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.OS_VERSION)) }
        osPatchLevel?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.OS_PATCH_LEVEL)) }
        attestationApplicationId?.toAsn1()?.let {
          add(DEROctetString(it).toTaggedObject(KeyMintTag.ATTESTATION_APPLICATION_ID))
        }
        attestationIdBrand?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_BRAND))
        }
        attestationIdDevice?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_DEVICE))
        }
        attestationIdProduct?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_PRODUCT))
        }
        attestationIdSerial?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_SERIAL))
        }
        attestationIdImei?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_IMEI)) }
        attestationIdMeid?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_MEID)) }
        attestationIdManufacturer?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_MANUFACTURER))
        }
        attestationIdModel?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_MODEL))
        }
        vendorPatchLevel?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.VENDOR_PATCH_LEVEL)) }
        bootPatchLevel?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.BOOT_PATCH_LEVEL)) }
        attestationIdSecondImei?.toAsn1()?.let {
          add(it.toTaggedObject(KeyMintTag.ATTESTATION_ID_SECOND_IMEI))
        }
        moduleHash?.toAsn1()?.let { add(it.toTaggedObject(KeyMintTag.MODULE_HASH)) }
      }
      .let { DERSequence(it.toTypedArray()) }

  internal companion object {
    fun from(seq: ASN1Sequence, validateTagOrder: Boolean = false): AuthorizationList {
      val objects =
        seq.associate {
          require(it is ASN1TaggedObject) {
            "Must be an ASN1TaggedObject, was ${it::class.simpleName}"
          }
          KeyMintTag.from(it.tagNo) to it.explicitBaseObject
        }

      /**
       * X.680 section 8.6
       *
       * The canonical order for tags is based on the outermost tag of each type and is defined as
       * follows:
       * 1. those elements or alternatives with universal class tags shall appear first, followed by
       *    those with application class tags, followed by those with context-specific tags,
       *    followed by those with private class tags;
       * 2. within each class of tags, the elements or alternatives shall appear in ascending order
       *    of their tag numbers.
       */
      // TODO: b/356172932 - Add test data once an example certificate is found in the wild.
      if (validateTagOrder && !objects.keys.zipWithNext().all { (lhs, rhs) -> rhs > lhs }) {
        throw IllegalArgumentException("AuthorizationList tags must appear in ascending order")
      }

      return AuthorizationList(
        purposes = objects[KeyMintTag.PURPOSE]?.toSet<ASN1Integer>()?.map { it.value }?.toSet(),
        algorithms = objects[KeyMintTag.ALGORITHM]?.toInt(),
        keySize = objects[KeyMintTag.KEY_SIZE]?.toInt(),
        digests = objects[KeyMintTag.DIGEST]?.toSet<ASN1Integer>()?.map { it.value }?.toSet(),
        paddings = objects[KeyMintTag.PADDING]?.toSet<ASN1Integer>()?.map { it.value }?.toSet(),
        ecCurve = objects[KeyMintTag.EC_CURVE]?.toInt(),
        rsaPublicExponent = objects[KeyMintTag.RSA_PUBLIC_EXPONENT]?.toInt(),
        activeDateTime = objects[KeyMintTag.ACTIVE_DATE_TIME]?.toInt(),
        originationExpireDateTime = objects[KeyMintTag.ORIGINATION_EXPIRE_DATE_TIME]?.toInt(),
        usageExpireDateTime = objects[KeyMintTag.USAGE_EXPIRE_DATE_TIME]?.toInt(),
        noAuthRequired = if (objects.containsKey(KeyMintTag.NO_AUTH_REQUIRED)) true else null,
        userAuthType = objects[KeyMintTag.USER_AUTH_TYPE]?.toInt(),
        authTimeout = objects[KeyMintTag.AUTH_TIMEOUT]?.toInt(),
        trustedUserPresenceRequired =
          if (objects.containsKey(KeyMintTag.TRUSTED_USER_PRESENCE_REQUIRED)) true else null,
        unlockedDeviceRequired =
          if (objects.containsKey(KeyMintTag.UNLOCKED_DEVICE_REQUIRED)) true else null,
        creationDateTime = objects[KeyMintTag.CREATION_DATE_TIME]?.toInt(),
        origin = objects[KeyMintTag.ORIGIN]?.toOrigin(),
        rollbackResistant = if (objects.containsKey(KeyMintTag.ROLLBACK_RESISTANT)) true else null,
        rootOfTrust = objects[KeyMintTag.ROOT_OF_TRUST]?.toRootOfTrust(),
        osVersion = objects[KeyMintTag.OS_VERSION]?.toInt(),
        osPatchLevel = objects[KeyMintTag.OS_PATCH_LEVEL]?.toPatchLevel(),
        attestationApplicationId =
          objects[KeyMintTag.ATTESTATION_APPLICATION_ID]?.toAttestationApplicationId(),
        attestationIdBrand = objects[KeyMintTag.ATTESTATION_ID_BRAND]?.toStr(),
        attestationIdDevice = objects[KeyMintTag.ATTESTATION_ID_DEVICE]?.toStr(),
        attestationIdProduct = objects[KeyMintTag.ATTESTATION_ID_PRODUCT]?.toStr(),
        attestationIdSerial = objects[KeyMintTag.ATTESTATION_ID_SERIAL]?.toStr(),
        attestationIdImei = objects[KeyMintTag.ATTESTATION_ID_IMEI]?.toStr(),
        attestationIdMeid = objects[KeyMintTag.ATTESTATION_ID_MEID]?.toStr(),
        attestationIdManufacturer = objects[KeyMintTag.ATTESTATION_ID_MANUFACTURER]?.toStr(),
        attestationIdModel = objects[KeyMintTag.ATTESTATION_ID_MODEL]?.toStr(),
        vendorPatchLevel = objects[KeyMintTag.VENDOR_PATCH_LEVEL]?.toPatchLevel(),
        bootPatchLevel = objects[KeyMintTag.BOOT_PATCH_LEVEL]?.toPatchLevel(),
        attestationIdSecondImei = objects[KeyMintTag.ATTESTATION_ID_SECOND_IMEI]?.toStr(),
        moduleHash = objects[KeyMintTag.MODULE_HASH]?.toByteString(),
      )
    }
  }
}

@Immutable
data class PatchLevel(val yearMonth: YearMonth, val version: Int? = null) {
  fun toAsn1(): ASN1Encodable = ASN1Integer(this.toString().toBigInteger())

  override fun toString(): String {
    val yearMonthString = DateTimeFormatter.ofPattern("yyyyMM").format(this.yearMonth)
    if (this.version != null) return String.format("$yearMonthString%02d", this.version)
    return yearMonthString
  }

  companion object {
    fun from(patchLevel: ASN1Encodable): PatchLevel? {
      check(patchLevel is ASN1Integer) { "Must be an ASN1Integer, was ${this::class.simpleName}" }
      return from(patchLevel.value.toString())
    }

    @JvmStatic
    fun from(patchLevel: String): PatchLevel? {
      if (patchLevel.length != 6 && patchLevel.length != 8) {
        return null
      }
      try {
        val yearMonth =
          DateTimeFormatter.ofPattern("yyyyMM").parse(patchLevel.substring(0, 6), YearMonth::from)
        val version = if (patchLevel.length == 8) patchLevel.substring(6).toInt() else null
        return PatchLevel(yearMonth, version)
      } catch (e: DateTimeParseException) {
        return null
      }
    }
  }
}

/**
 * Representation of the AttestationApplicationId sequence contained within [AuthorizationList].
 *
 * @see
 *   https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema
 */
@Immutable
data class AttestationApplicationId(
  @SuppressWarnings("Immutable") val packages: Set<AttestationPackageInfo>,
  @SuppressWarnings("Immutable") val signatures: Set<ByteString>,
) {
  fun toAsn1() =
    buildList {
        add(DERSet(packages.map { it.toAsn1() }.toTypedArray()))
        add(DERSet(signatures.map { it.toAsn1() }.toTypedArray()))
      }
      .let { DERSequence(it.toTypedArray()) }

  internal companion object {
    fun from(seq: ASN1Sequence): AttestationApplicationId {
      require(seq.size() == 2)
      val attestationPackageInfos = (seq.getObjectAt(0).toSet<ASN1Sequence>())
      val signatureDigests = seq.getObjectAt(1).toSet<ASN1OctetString>()
      return AttestationApplicationId(
        attestationPackageInfos.map { AttestationPackageInfo.from(it) }.toSet(),
        signatureDigests.map { it.toByteString() }.toSet(),
      )
    }
  }
}

/**
 * Representation of the AttestationPackageInfo sequence contained within
 * [AttestationApplicationId].
 *
 * @see
 *   https://source.android.com/docs/security/features/keystore/attestation#attestationapplicationid-schema
 */
data class AttestationPackageInfo(val name: String, val version: BigInteger) {
  fun toAsn1() =
    buildList {
        add(name.toAsn1())
        add(version.toAsn1())
      }
      .let { DERSequence(it.toTypedArray()) }

  internal companion object {
    fun from(attestationPackageInfo: ASN1Sequence): AttestationPackageInfo {
      require(attestationPackageInfo.size() == 2) {
        "AttestationPackageInfo sequence must have 2 elements, had ${attestationPackageInfo.size()}"
      }
      return AttestationPackageInfo(
        name = attestationPackageInfo.getObjectAt(0).toStr(),
        version = attestationPackageInfo.getObjectAt(1).toInt(),
      )
    }
  }
}

/**
 * Representation of the RootOfTrust sequence contained within [AuthorizationList].
 *
 * @see https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields
 */
@Immutable
data class RootOfTrust(
  val verifiedBootKey: ByteString,
  val deviceLocked: Boolean,
  val verifiedBootState: VerifiedBootState,
  val verifiedBootHash: ByteString? = null,
) {
  fun toAsn1() =
    buildList {
        add(verifiedBootKey.toAsn1())
        add(deviceLocked.toAsn1())
        add(verifiedBootState.toAsn1())
        verifiedBootHash?.let { add(it.toAsn1()) }
      }
      .let { DERSequence(it.toTypedArray()) }

  internal companion object {
    fun from(rootOfTrust: ASN1Sequence): RootOfTrust {
      require(rootOfTrust.size() == 3 || rootOfTrust.size() == 4)
      val verifiedBootState = rootOfTrust.getObjectAt(2).toEnumerated()
      return RootOfTrust(
        verifiedBootKey = rootOfTrust.getObjectAt(0).toByteString(),
        deviceLocked = rootOfTrust.getObjectAt(1).toBoolean(),
        VerifiedBootState.from(verifiedBootState),
        verifiedBootHash =
          if (rootOfTrust.size() > 3) rootOfTrust.getObjectAt(3).toByteString() else null,
      )
    }
  }
}

/**
 * Representation of the VerifiedBootState enum contained within [RootOfTrust].
 *
 * @see
 *   https://source.android.com/docs/security/features/keystore/attestation#verifiedbootstate-values
 */
enum class VerifiedBootState(val value: Int) {
  VERIFIED(0),
  SELF_SIGNED(1),
  UNVERIFIED(2),
  FAILED(3);

  fun toAsn1(): ASN1Enumerated = ASN1Enumerated(value)

  companion object {
    fun from(value: ASN1Enumerated) =
      values().firstOrNull { it.value == value.intValueExact() }
        ?: throw IllegalArgumentException("unknown value: ${value.intValueExact()}")
  }
}

private fun ASN1Encodable.toAttestationApplicationId(): AttestationApplicationId {
  require(this is ASN1OctetString) {
    "Object must be an ASN1OctetString, was ${this::class.simpleName}"
  }
  return AttestationApplicationId.from(ASN1Sequence.getInstance(this.octets))
}

// TODO: b/356172932 - `validateTagOrder` should default to true after making it user configurable.
private fun ASN1Encodable.toAuthorizationList(
  validateTagOrder: Boolean = false
): AuthorizationList {
  check(this is ASN1Sequence) { "Object must be an ASN1Sequence, was ${this::class.simpleName}" }
  return AuthorizationList.from(this, validateTagOrder)
}

private fun ASN1Encodable.toBoolean(): Boolean {
  check(this is ASN1Boolean) { "Must be an ASN1Boolean, was ${this::class.simpleName}" }
  return this.isTrue
}

private fun ASN1Encodable.toByteArray(): ByteArray {
  check(this is ASN1OctetString) { "Must be an ASN1OctetString, was ${this::class.simpleName}" }
  return this.octets
}

private fun ASN1Encodable.toByteBuffer() = ByteBuffer.wrap(this.toByteArray())

private fun ASN1Encodable.toByteString() = ByteString.copyFrom(this.toByteArray())

private fun ASN1Encodable.toEnumerated(): ASN1Enumerated {
  check(this is ASN1Enumerated) { "Must be an ASN1Enumerated, was ${this::class.simpleName}" }
  return this
}

private fun ASN1Encodable.toInt(): BigInteger {
  check(this is ASN1Integer) { "Must be an ASN1Integer, was ${this::class.simpleName}" }
  return this.value
}

private fun ASN1Encodable.toPatchLevel(): PatchLevel? = PatchLevel.from(this)

private fun ASN1Encodable.toRootOfTrust(): RootOfTrust {
  check(this is ASN1Sequence) { "Object must be an ASN1Sequence, was ${this::class.simpleName}" }
  return RootOfTrust.from(this)
}

private fun ASN1Encodable.toSecurityLevel(): SecurityLevel =
  SecurityLevel.values().firstOrNull { it.value.toBigInteger() == this.toEnumerated().value }
    ?: throw IllegalStateException("unknown value: ${this.toEnumerated().value}")

private fun ASN1Encodable.toOrigin(): Origin =
  Origin.values().firstOrNull { it.value.toBigInteger() == this.toInt() }
    ?: throw IllegalStateException("unknown value: ${this.toInt()}")

private inline fun <reified T> ASN1Encodable.toSet(): Set<T> {
  check(this is ASN1Set) { "Object must be an ASN1Set, was ${this::class.simpleName}" }
  return this.map {
      check(it is T) { "Object must be a ${T::class.simpleName}, was ${this::class.simpleName}" }
      it
    }
    .toSet()
}

private fun ASN1Encodable.toStr() =
  UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(this.toByteBuffer())
    .toString()

private fun ASN1Encodable.toTaggedObject(tag: KeyMintTag) = DERTaggedObject(tag.value, this)

private fun BigInteger.toAsn1() = ASN1Integer(this)

private fun Boolean.toAsn1() = ASN1Boolean.getInstance(this)

private fun ByteString.toAsn1() = DEROctetString(this.toByteArray())

private fun Set<BigInteger>.toAsn1() = DERSet(this.map { it.toAsn1() }.toTypedArray())

private fun String.toAsn1() = DEROctetString(this.toByteArray(UTF_8))

fun cborDecode(data: ByteArray): DataItem {
  val bais = ByteArrayInputStream(data)
  val dataItems = CborDecoder(bais).decode()
  if (dataItems.size != 1) {
    throw CborException(
      "Byte stream cannot be decoded properly. Expected 1 item, found ${dataItems.size}"
    )
  }
  return dataItems[0]
}

fun cborEncode(dataItem: DataItem): ByteArray {
  val baos = ByteArrayOutputStream()
  val encoder = CborEncoder(baos)
  encoder.encode(dataItem)
  return baos.toByteArray()
}

fun DataItem.asInteger(): Int {
  if (this.majorType == MajorType.UNSIGNED_INTEGER) {
    return (this as UnsignedInteger).value.toInt()
  }
  if (this.majorType == MajorType.NEGATIVE_INTEGER) {
    return (this as NegativeInteger).value.toInt()
  }
  throw CborException("Expected a number, got ${this.majorType}")
}

fun Int.asDataItem() =
  when {
    this >= 0 -> UnsignedInteger(this.toLong())
    else -> NegativeInteger(this.toLong())
  }

fun String.asDataItem() = UnicodeString(this)

private fun DataItem.asMap(): Map {
  if (this.majorType != MajorType.MAP) {
    throw CborException("Expected a map, got ${this.majorType.name}")
  }
  @Suppress("UNCHECKED_CAST")
  return this as Map
}

fun DataItem.asUnicodeString(): UnicodeString {
  if (this.majorType != MajorType.UNICODE_STRING) {
    throw CborException("Expected a unicode string, got ${this.majorType.name}")
  }
  return this as UnicodeString
}

fun DataItem.asString(): String {
  return this.asUnicodeString().string
}

private fun Long.asUnsignedInteger() = co.nstant.`in`.cbor.model.UnsignedInteger(this)
