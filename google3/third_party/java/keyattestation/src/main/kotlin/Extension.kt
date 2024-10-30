package com.google.wireless.android.security.attestationverifier

import com.google.protobuf.ByteString
import com.squareup.moshi.JsonClass
import java.math.BigInteger
import java.security.cert.X509Certificate
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

@JsonClass(generateAdapter = true)
data class KeyDescription(
  val attestationVersion: BigInteger,
  val attestationSecurityLevel: SecurityLevel,
  val keymasterVersion: BigInteger,
  val keymasterSecurityLevel: SecurityLevel,
  val attestationChallenge: ByteString,
  val uniqueId: ByteString,
  val softwareEnforced: AuthorizationList,
  val teeEnforced: AuthorizationList,
) {
  fun asExtension(): Extension {
    return Extension(OID, /* critical= */ false, encodeToAsn1())
  }

  fun encodeToAsn1(): ByteArray =
    buildList {
        add(attestationVersion.toAsn1())
        add(attestationSecurityLevel.toAsn1())
        add(keymasterVersion.toAsn1())
        add(keymasterSecurityLevel.toAsn1())
        add(attestationChallenge.toAsn1())
        add(uniqueId.toAsn1())
        add(softwareEnforced.toAsn1())
        add(teeEnforced.toAsn1())
      }
      .let { DERSequence(it.toTypedArray()).encoded }

  companion object {
    /* OID for the key attestation extension.
     * https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
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
        // http://google3/third_party/java_src/bouncycastle/core/src/main/java/org/bouncycastle/asn1/ASN1UniversalType.java;l=24;rcl=484684674
        throw IllegalArgumentException(e)
      }

    private fun from(seq: ASN1Sequence): KeyDescription {
      require(seq.size() == 8)
      return KeyDescription(
        attestationVersion = seq.getObjectAt(0).asInt(),
        attestationSecurityLevel = seq.getObjectAt(1).asSecurityLevel(),
        keymasterVersion = seq.getObjectAt(2).asInt(),
        keymasterSecurityLevel = seq.getObjectAt(3).asSecurityLevel(),
        attestationChallenge = seq.getObjectAt(4).asByteString(),
        uniqueId = seq.getObjectAt(5).asByteString(),
        softwareEnforced = seq.getObjectAt(6).asAuthorizationList(),
        teeEnforced = seq.getObjectAt(7).asAuthorizationList(),
      )
    }
  }
}

/**
 * Representation of the SecurityLevel enum contained within [KeyDescription].
 *
 * @see
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_authorizationlist
 */
enum class SecurityLevel(val value: Int) {
  // LINT.IfChange(security_level)
  SOFTWARE(0),
  TRUSTED_ENVIRONMENT(1),
  STRONG_BOX(2);

  // LINT.ThenChange(//depot/google3/identity/cryptauth/apparat/apparat.proto:key_type,
  // //depot/google3/identity/cryptauth/apparat/storage/apparat_storage_api.proto:keymaster_security_level)

  internal fun toAsn1() = ASN1Enumerated(value)
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
  TRUSTED_USER_PRESENCE_REQUIRED(507),
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
  ATTESTATION_ID_SECOND_IMEI(723);

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
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_authorizationlist
 */
@JsonClass(generateAdapter = true)
data class AuthorizationList(
  val purposes: Set<BigInteger>? = null,
  val keySize: BigInteger? = null,
  val algorithms: BigInteger? = null,
  val digests: Set<BigInteger>? = null,
  val paddings: Set<BigInteger>? = null,
  val ecCurve: BigInteger? = null,
  val rsaPublicExponent: BigInteger? = null,
  val activeDateTime: BigInteger? = null,
  val originationExpireDateTime: BigInteger? = null,
  val usageExpireDateTime: BigInteger? = null,
  val noAuthRequired: Boolean? = null,
  val userAuthType: BigInteger? = null,
  val authTimeout: BigInteger? = null,
  val trustedUserPresenceRequired: Boolean? = null,
  val creationDateTime: BigInteger? = null,
  val origin: BigInteger? = null,
  val rollbackResistant: Boolean? = null,
  val rootOfTrust: RootOfTrust? = null,
  val osVersion: BigInteger? = null,
  val osPatchLevel: BigInteger? = null,
  val attestationApplicationId: AttestationApplicationId? = null,
  val attestationIdBrand: String? = null,
  val attestationIdDevice: String? = null,
  val attestationIdProduct: String? = null,
  val attestationIdSerial: String? = null,
  val attestationIdImei: String? = null,
  val attestationIdMeid: String? = null,
  val attestationIdManufacturer: String? = null,
  val attestationIdModel: String? = null,
  val vendorPatchLevel: BigInteger? = null,
  val bootPatchLevel: BigInteger? = null,
  val attestationIdSecondImei: String? = null,
) {
  /**
   * Converts the representation of an [AuthorizationList] to an ASN.1 sequence.
   *
   * Properties that are null are not included in the sequence.
   */
  internal fun toAsn1() =
    buildList {
        purposes?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.PURPOSE)) }
        algorithms?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ALGORITHM)) }
        keySize?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.KEY_SIZE)) }
        digests?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.DIGEST)) }
        paddings?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.PADDING)) }
        ecCurve?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.EC_CURVE)) }
        rsaPublicExponent?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.RSA_PUBLIC_EXPONENT)) }
        activeDateTime?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ACTIVE_DATE_TIME)) }
        originationExpireDateTime?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ORIGINATION_EXPIRE_DATE_TIME))
        }
        usageExpireDateTime?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.USAGE_EXPIRE_DATE_TIME))
        }
        if (noAuthRequired != null) {
          check(noAuthRequired) { "noAuthRequired must be null or true" }
          add(DERNull.INSTANCE.asTaggedObject(KeyMintTag.NO_AUTH_REQUIRED))
        }
        userAuthType?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.USER_AUTH_TYPE)) }
        authTimeout?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.AUTH_TIMEOUT)) }
        if (trustedUserPresenceRequired != null) {
          check(trustedUserPresenceRequired) { "trustedUserPresenceRequired must be null or true" }
          add(DERNull.INSTANCE.asTaggedObject(KeyMintTag.TRUSTED_USER_PRESENCE_REQUIRED))
        }
        creationDateTime?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.CREATION_DATE_TIME)) }
        origin?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ORIGIN)) }
        if (rollbackResistant != null) {
          check(rollbackResistant) { "rollbackResistant must be null or true" }
          add(DERNull.INSTANCE.asTaggedObject(KeyMintTag.ROLLBACK_RESISTANT))
        }
        rootOfTrust?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ROOT_OF_TRUST)) }
        osVersion?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.OS_VERSION)) }
        osPatchLevel?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.OS_PATCH_LEVEL)) }
        attestationApplicationId?.toAsn1()?.let {
          add(DEROctetString(it).asTaggedObject(KeyMintTag.ATTESTATION_APPLICATION_ID))
        }
        attestationIdBrand?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_BRAND))
        }
        attestationIdDevice?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_DEVICE))
        }
        attestationIdProduct?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_PRODUCT))
        }
        attestationIdSerial?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_SERIAL))
        }
        attestationIdImei?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_IMEI)) }
        attestationIdMeid?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_MEID)) }
        attestationIdManufacturer?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_MANUFACTURER))
        }
        attestationIdModel?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_MODEL))
        }
        vendorPatchLevel?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.VENDOR_PATCH_LEVEL)) }
        bootPatchLevel?.toAsn1()?.let { add(it.asTaggedObject(KeyMintTag.BOOT_PATCH_LEVEL)) }
        attestationIdSecondImei?.toAsn1()?.let {
          add(it.asTaggedObject(KeyMintTag.ATTESTATION_ID_SECOND_IMEI))
        }
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
        purposes = objects[KeyMintTag.PURPOSE]?.asSetOf<ASN1Integer>()?.map { it.value }?.toSet(),
        algorithms = objects[KeyMintTag.ALGORITHM]?.asInt(),
        keySize = objects[KeyMintTag.KEY_SIZE]?.asInt(),
        digests = objects[KeyMintTag.DIGEST]?.asSetOf<ASN1Integer>()?.map { it.value }?.toSet(),
        paddings = objects[KeyMintTag.PADDING]?.asSetOf<ASN1Integer>()?.map { it.value }?.toSet(),
        ecCurve = objects[KeyMintTag.EC_CURVE]?.asInt(),
        rsaPublicExponent = objects[KeyMintTag.RSA_PUBLIC_EXPONENT]?.asInt(),
        activeDateTime = objects[KeyMintTag.ACTIVE_DATE_TIME]?.asInt(),
        originationExpireDateTime = objects[KeyMintTag.ORIGINATION_EXPIRE_DATE_TIME]?.asInt(),
        usageExpireDateTime = objects[KeyMintTag.USAGE_EXPIRE_DATE_TIME]?.asInt(),
        noAuthRequired = if (objects.containsKey(KeyMintTag.NO_AUTH_REQUIRED)) true else null,
        userAuthType = objects[KeyMintTag.USER_AUTH_TYPE]?.asInt(),
        authTimeout = objects[KeyMintTag.AUTH_TIMEOUT]?.asInt(),
        trustedUserPresenceRequired =
          if (objects.containsKey(KeyMintTag.TRUSTED_USER_PRESENCE_REQUIRED)) true else null,
        creationDateTime = objects[KeyMintTag.CREATION_DATE_TIME]?.asInt(),
        origin = objects[KeyMintTag.ORIGIN]?.asInt(),
        rollbackResistant = if (objects.containsKey(KeyMintTag.ROLLBACK_RESISTANT)) true else null,
        rootOfTrust = objects[KeyMintTag.ROOT_OF_TRUST]?.asRootOfTrust(),
        osVersion = objects[KeyMintTag.OS_VERSION]?.asInt(),
        osPatchLevel = objects[KeyMintTag.OS_PATCH_LEVEL]?.asInt(),
        attestationApplicationId =
          objects[KeyMintTag.ATTESTATION_APPLICATION_ID]?.asAttestationApplicationId(),
        attestationIdBrand = objects[KeyMintTag.ATTESTATION_ID_BRAND]?.asString(),
        attestationIdDevice = objects[KeyMintTag.ATTESTATION_ID_DEVICE]?.asString(),
        attestationIdProduct = objects[KeyMintTag.ATTESTATION_ID_PRODUCT]?.asString(),
        attestationIdSerial = objects[KeyMintTag.ATTESTATION_ID_SERIAL]?.asString(),
        attestationIdImei = objects[KeyMintTag.ATTESTATION_ID_IMEI]?.asString(),
        attestationIdMeid = objects[KeyMintTag.ATTESTATION_ID_MEID]?.asString(),
        attestationIdManufacturer = objects[KeyMintTag.ATTESTATION_ID_MANUFACTURER]?.asString(),
        attestationIdModel = objects[KeyMintTag.ATTESTATION_ID_MODEL]?.asString(),
        vendorPatchLevel = objects[KeyMintTag.VENDOR_PATCH_LEVEL]?.asInt(),
        bootPatchLevel = objects[KeyMintTag.BOOT_PATCH_LEVEL]?.asInt(),
        attestationIdSecondImei = objects[KeyMintTag.ATTESTATION_ID_SECOND_IMEI]?.asString(),
      )
    }
  }
}

/**
 * Representation of the AttestationApplicationId sequence contained within [AuthorizationList].
 *
 * @see
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_attestationid
 */
@JsonClass(generateAdapter = true)
data class AttestationApplicationId(
  val packages: Set<AttestationPackageInfo>,
  val signatures: Set<ByteString>,
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
      val attestationPackageInfos = (seq.getObjectAt(0).asSetOf<ASN1Sequence>())
      val signatureDigests = seq.getObjectAt(1).asSetOf<ASN1OctetString>()
      return AttestationApplicationId(
        attestationPackageInfos.map { AttestationPackageInfo.from(it) }.toSet(),
        signatureDigests.map { it.asByteString() }.toSet(),
      )
    }
  }
}

/**
 * Representation of the AttestationPackageInfo sequence contained within
 * [AttestationApplicationId].
 *
 * @see
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_attestationid
 */
@JsonClass(generateAdapter = true)
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
        name = attestationPackageInfo.getObjectAt(0).asString(),
        version = attestationPackageInfo.getObjectAt(1).asInt(),
      )
    }
  }
}

/**
 * Representation of the RootOfTrust sequence contained within [AuthorizationList].
 *
 * @see
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_rootoftrust
 */
@JsonClass(generateAdapter = true)
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
      val verifiedBootState = rootOfTrust.getObjectAt(2).asEnumerated()
      return RootOfTrust(
        verifiedBootKey = rootOfTrust.getObjectAt(0).asByteString(),
        deviceLocked = rootOfTrust.getObjectAt(1).asBoolean(),
        VerifiedBootState.from(verifiedBootState),
        verifiedBootHash =
          if (rootOfTrust.size() > 3) rootOfTrust.getObjectAt(3).asByteString() else null,
      )
    }
  }
}

/**
 * Representation of the VerifiedBootState enum contained within [RootOfTrust].
 *
 * @see
 *   https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_verifiedbootstate
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

private fun ASN1Encodable.asAttestationApplicationId(): AttestationApplicationId {
  require(this is ASN1OctetString) {
    "Object must be an ASN1OctetString, was ${this::class.simpleName}"
  }
  return AttestationApplicationId.from(ASN1Sequence.getInstance(this.octets))
}

// TODO: b/356172932 - `validateTagOrder` should default to true after making it user configurable.
private fun ASN1Encodable.asAuthorizationList(
  validateTagOrder: Boolean = false
): AuthorizationList {
  check(this is ASN1Sequence) { "Object must be an ASN1Sequence, was ${this::class.simpleName}" }
  return AuthorizationList.from(this, validateTagOrder)
}

private fun ASN1Encodable.asBoolean(): Boolean {
  check(this is ASN1Boolean) { "Must be an ASN1Boolean, was ${this::class.simpleName}" }
  return this.isTrue
}

private fun ASN1Encodable.asByteArray(): ByteArray {
  check(this is ASN1OctetString) { "Must be an ASN1OctetString, was ${this::class.simpleName}" }
  return this.octets
}

private fun ASN1Encodable.asByteString() = ByteString.copyFrom(this.asByteArray())

private fun ASN1Encodable.asEnumerated(): ASN1Enumerated {
  check(this is ASN1Enumerated) { "Must be an ASN1Enumerated, was ${this::class.simpleName}" }
  return this
}

private fun ASN1Encodable.asInt(): BigInteger {
  check(this is ASN1Integer) { "Must be an ASN1Integer, was ${this::class.simpleName}" }
  return this.value
}

private fun ASN1Encodable.asRootOfTrust(): RootOfTrust {
  check(this is ASN1Sequence) { "Object must be an ASN1Sequence, was ${this::class.simpleName}" }
  return RootOfTrust.from(this)
}

private fun ASN1Encodable.asSecurityLevel(): SecurityLevel =
  SecurityLevel.values().firstOrNull { it.value.toBigInteger() == this.asEnumerated().value }
    ?: throw IllegalStateException("unknown value: ${this.asEnumerated().value}")

private inline fun <reified T> ASN1Encodable.asSetOf(): Set<T> {
  check(this is ASN1Set) { "Object must be an ASN1Set, was ${this::class.simpleName}" }
  return this.map {
      check(it is T) { "Object must be a ${T::class.simpleName}, was ${this::class.simpleName}" }
      it
    }
    .toSet()
}

private fun ASN1Encodable.asString() = this.asByteArray().toString(UTF_8)

private fun ASN1Encodable.asTaggedObject(tag: KeyMintTag) = DERTaggedObject(tag.value, this)

private fun BigInteger.toAsn1() = ASN1Integer(this)

private fun Boolean.toAsn1() = ASN1Boolean.getInstance(this)

private fun ByteString.toAsn1() = DEROctetString(this.toByteArray())

private fun Set<BigInteger>.toAsn1() = DERSet(this.map { it.toAsn1() }.toTypedArray())

private fun String.toAsn1() = DEROctetString(this.toByteArray(UTF_8))
