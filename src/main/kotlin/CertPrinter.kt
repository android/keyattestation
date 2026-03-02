/*
 * Copyright 2025 Google LLC
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

import com.google.protobuf.ByteString
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Date

/**
 * Representation of the KeyPurpose enum contained within [AuthorizationList].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
 */
enum class KeyPurpose(val value: Int) {
  ENCRYPT(0),
  DECRYPT(1),
  SIGN(2),
  VERIFY(3),
  WRAP_KEY(5),
  AGREE_KEY(6),
  ATTEST_KEY(7);

  companion object {
    fun fromInt(value: Int) = values().firstOrNull { it.value == value }
  }
}

/**
 * Representation of the Algorithm enum contained within [AuthorizationList].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Algorithm.aidl
 */
enum class KeyAlgorithm(val value: Int) {
  RSA(1),
  EC(3),
  AES(32),
  TRIPLE_DES(33),
  HMAC(128);

  companion object {
    fun fromInt(value: Int) = values().firstOrNull { it.value == value }
  }
}

/**
 * Representation of the ECCurve enum contained within [AuthorizationList].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl
 */
enum class EcCurve(val value: Int) {
  P_224(0),
  P_256(1),
  P_384(2),
  P_521(3),
  CURVE_25519(4);

  companion object {
    fun fromInt(value: Int) = values().firstOrNull { it.value == value }
  }
}

/**
 * Representation of the BlockMode enum contained within [AuthorizationList].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/BlockMode.aidl
 */
enum class BlockMode(val value: Int) {
  ECB(1),
  CBC(2),
  CTR(3),
  GCM(32);

  companion object {
    fun fromInt(value: Int) = values().firstOrNull { it.value == value }
  }
}

/**
 * Representation of the Digest enum contained within [AuthorizationList].
 *
 * @see
 *   https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Digest.aidl
 */
enum class Digest(val value: Int) {
  NONE(0),
  MD5(1),
  SHA1(2),
  SHA_2_224(3),
  SHA_2_256(4),
  SHA_2_384(5),
  SHA_2_512(6);

  companion object {
    fun fromInt(value: Int) = values().firstOrNull { it.value == value }
  }
}

/**
 * Constructs pretty-printed strings for various parts of an Android Key Attestation certificate.
 */
object CertPrinter {
  private var indentLevel = 0
  private val dateFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneId.of("UTC"))

  private fun formatDate(date: Date): String = dateFormatter.format(date.toInstant())

  private fun indent(block: () -> Unit) {
    indentLevel++
    AutoCloseable { indentLevel-- }.use { block() }
  }

  private fun StringBuilder.appendIndentedLine(value: Any) {
    repeat(indentLevel) { append("    ") }
    appendLine(value)
  }

  /** Returns a pretty-printed string representation of the given [X509Certificate]. */
  fun prettyString(cert: X509Certificate): String = buildString {
    appendIndentedLine("X.509 Certificate:")
    indent {
      appendIndentedLine("Version: ${cert.version}")
      appendIndentedLine("Serial Number: ${cert.serialNumber.toString(16)}")
      appendIndentedLine("Signature Algorithm: ${cert.sigAlgName}")
      appendIndentedLine("Issuer: ${cert.issuerX500Principal}")
      appendIndentedLine("Validity:")
      indent {
        appendIndentedLine("Not Before: ${formatDate(cert.notBefore)}")
        appendIndentedLine("Not After: ${formatDate(cert.notAfter)}")
      }
      appendIndentedLine("Subject: ${cert.subjectX500Principal}")
      appendIndentedLine("Public Key Algorithm: ${cert.publicKey.algorithm}")
    }
    appendIndentedLine("Custom Extensions:")
    indent {
      KeyDescription.parseFrom(cert)?.let { append(prettyString(it)) }
      ProvisioningInfoMap.parseFrom(cert)?.let { append(prettyString(it)) }
    }
  }

  /** Returns a pretty-printed string representation of the given [ProvisioningInfoMap]. */
  fun prettyString(info: ProvisioningInfoMap): String = buildString {
    appendIndentedLine("Provisioning Info:")
    indent {
      appendIndentedLine("certificatesIssued: ${info.certificatesIssued}")
    }
  }

  /** Returns a pretty-printed string representation of the given [KeyDescription]. */
  fun prettyString(description: KeyDescription): String = buildString {
    appendIndentedLine("Key Description:")
    indent {
      appendIndentedLine("attestationVersion: ${description.attestationVersion}")
      appendIndentedLine("attestationSecurityLevel: ${description.attestationSecurityLevel}")
      appendIndentedLine("keyMintVersion: ${description.keyMintVersion}")
      appendIndentedLine("keyMintSecurityLevel: ${description.keyMintSecurityLevel}")
      appendIndentedLine("attestationChallenge: ${description.attestationChallenge.toHex()}")
      appendIndentedLine("uniqueId: ${description.uniqueId.toHex()}")
      appendIndentedLine("softwareEnforced:")
      indent { append(description.softwareEnforced.prettyString()) }
      appendIndentedLine("hardwareEnforced:")
      indent { append(description.hardwareEnforced.prettyString()) }
    }
  }

  private fun AuthorizationList.prettyString(): String = buildString {
    if (purposes != null) appendIndentedLine("purposes: ${purposes?.toKeyPurposes()}")
    if (algorithms != null) appendIndentedLine("algorithms: ${algorithms?.toKeyAlgorithm()}")
    if (keySize != null) appendIndentedLine("keySize: $keySize")
    if (blockModes != null) appendIndentedLine("blockModes: ${blockModes?.toBlockModes()}")
    if (digests != null) appendIndentedLine("digests: ${digests?.toDigests()}")
    if (paddings != null) appendIndentedLine("paddings: $paddings")
    if (ecCurve != null) appendIndentedLine("ecCurve: ${ecCurve?.toEcCurve()}")
    if (rsaPublicExponent != null) appendIndentedLine("rsaPublicExponent: $rsaPublicExponent")
    if (rsaOaepMgfDigests != null) {
      appendIndentedLine("rsaOaepMgfDigests: ${rsaOaepMgfDigests?.toDigests()}")
    }
    if (activeDateTime != null) appendIndentedLine("activeDateTime: $activeDateTime")
    if (originationExpireDateTime != null) {
      appendIndentedLine("originationExpireDateTime: $originationExpireDateTime")
    }
    if (usageExpireDateTime != null) appendIndentedLine("usageExpireDateTime: $usageExpireDateTime")
    if (noAuthRequired != null) appendIndentedLine("noAuthRequired: $noAuthRequired")
    if (userAuthType != null) appendIndentedLine("userAuthType: $userAuthType")
    if (authTimeout != null) appendIndentedLine("authTimeout: $authTimeout")
    if (trustedUserPresenceRequired != null) {
      appendIndentedLine("trustedUserPresenceRequired: $trustedUserPresenceRequired")
    }
    if (unlockedDeviceRequired != null) {
      appendIndentedLine("unlockedDeviceRequired: $unlockedDeviceRequired")
    }
    if (creationDateTime != null) {
      appendIndentedLine("creationDateTime: ${creationDateTime?.toDateTime()}")
    }
    if (origin != null) appendIndentedLine("origin: $origin")
    if (rollbackResistant != null) appendIndentedLine("rollbackResistant: $rollbackResistant")
    if (rootOfTrust != null) {
      appendIndentedLine("rootOfTrust:")
      indent { append(rootOfTrust?.prettyString()) }
    }
    if (osVersion != null) appendIndentedLine("osVersion: $osVersion")
    if (osPatchLevel != null) appendIndentedLine("osPatchLevel: $osPatchLevel")
    if (attestationApplicationId != null) {
      appendIndentedLine("attestationApplicationId:")
      indent { append(attestationApplicationId?.prettyString()) }
    }
    if (attestationIdBrand != null) appendIndentedLine("attestationIdBrand: $attestationIdBrand")
    if (attestationIdDevice != null) appendIndentedLine("attestationIdDevice: $attestationIdDevice")
    if (attestationIdProduct != null) {
      appendIndentedLine("attestationIdProduct: $attestationIdProduct")
    }
    if (attestationIdSerial != null) appendIndentedLine("attestationIdSerial: $attestationIdSerial")
    if (attestationIdImei != null) appendIndentedLine("attestationIdImei: $attestationIdImei")
    if (attestationIdMeid != null) appendIndentedLine("attestationIdMeid: $attestationIdMeid")
    if (attestationIdManufacturer != null) {
      appendIndentedLine("attestationIdManufacturer: $attestationIdManufacturer")
    }
    if (attestationIdModel != null) appendIndentedLine("attestationIdModel: $attestationIdModel")
    if (vendorPatchLevel != null) appendIndentedLine("vendorPatchLevel: $vendorPatchLevel")
    if (bootPatchLevel != null) appendIndentedLine("bootPatchLevel: $bootPatchLevel")
    if (attestationIdSecondImei != null) {
      appendIndentedLine("attestationIdSecondImei: $attestationIdSecondImei")
    }
    if (moduleHash != null) appendIndentedLine("moduleHash: ${moduleHash?.toHex()}")
  }

  private fun AttestationApplicationId.prettyString(): String = buildString {
    appendIndentedLine("packages:")
    indent {
      for (p in packages) {
        append(p.prettyString())
      }
    }
    appendIndentedLine("signatures:")
    indent {
      for (s in signatures) {
        append(s.prettyString())
      }
    }
  }

  private fun ByteString.prettyString(): String = buildString { appendIndentedLine(toHex()) }

  private fun ByteString.toHex(): String =
    if (this.isEmpty) "\"\"" else joinToString("") { "%02x".format(it) }

  private fun AttestationPackageInfo.prettyString(): String = buildString {
    appendIndentedLine("name: $name, version: $version")
  }

  private fun RootOfTrust.prettyString(): String = buildString {
    appendIndentedLine("verifiedBootKey: ${verifiedBootKey.toHex()}")
    appendIndentedLine("deviceLocked: $deviceLocked")
    appendIndentedLine("verifiedBootState: $verifiedBootState")
    appendIndentedLine("verifiedBootHash: ${verifiedBootHash?.toHex() ?: "\"\""}")
  }

  private fun Set<BigInteger>.toBlockModes(): Set<BlockMode?> =
    this.map { BlockMode.fromInt(it.toInt()) }.toSet()

  private fun Set<BigInteger>.toDigests(): Set<Digest?> =
    this.map { Digest.fromInt(it.toInt()) }.toSet()

  private fun Set<BigInteger>.toKeyPurposes(): Set<KeyPurpose?> =
    this.map { KeyPurpose.fromInt(it.toInt()) }.toSet()

  private fun BigInteger.toKeyAlgorithm(): KeyAlgorithm? = KeyAlgorithm.fromInt(this.toInt())

  private fun BigInteger.toEcCurve(): EcCurve? = EcCurve.fromInt(this.toInt())

  private fun BigInteger.toDateTime(): String =
    if (this.toLong() < 0L) "" else Instant.ofEpochMilli(this.toLong()).toString()
}
