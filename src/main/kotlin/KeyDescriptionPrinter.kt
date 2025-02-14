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

import com.google.common.flags.Flag
import com.google.common.flags.FlagSpec
import com.google.common.flags.Flags
import com.google.protobuf.ByteString

/*
 * This is a sample input/output to show how to use this binary.
 *
 * Usage:
 *
 * ```
 * blaze run //third_party/java/keyattestation/src/main/kotlin:key_description_printer -- --certificate=MIIB7jCCAS6...
 *
 * Output:
 *
 * KeyDescription:
 *   attestationVersion: 300
 *   attestationSecurityLevel: TRUSTED_ENVIRONMENT
 *   keymasterVersion: 300
 *   keymasterSecurityLevel: TRUSTED_ENVIRONMENT
 *   attestationChallenge: 0000000000000000000000000000000000000000000000000000000000000000
 *   uniqueId: 0000000000000000000000000000000000000000000000000000000000000000
 *   softwareEnforced:
 *     creationDateTime: 2025-01-01T00:00:00Z
 *     attestationApplicationId:
 *       packages:
 *         name: com.android.keyattestation.verifier
 *         version: 1
 *       signatures:
 *         0000000000000000000000000000000000000000000000000000000000000000
 *   teeEnforced:
 *     purposes: [2]
 *     keySize: 256
 *     algorithms: 3
 *     digests: [4]
 *     ecCurve: 1
 *     noauthRequired: true
 *     origin: ORIGIN_UNSPECIFIED
 *     rootOfTrust:
 *       verifiedBootKey: 000000000000000000000000000000000000000000000000000000000000000
 *       deviceLocked: false
 *       verifiedBootState: UNVERIFIED
 *       verifiedBootHash: 0000000000000000000000000000000000000000000000000000000000000000
 *.    attestationIdBrand: google
 *.    attestationIdDevice: oriole
 *.    attestationIdProduct: oriole
 *.    attestationIdManufacturer: Google
 *.    attestationIdModel: Pixel 6
 *.    vendorPatchLevel: 20250101
 *.    bootPatchLevel: 20250101
 * ```
 */

object KeyDescriptionPrinter {
  @FlagSpec(name = "certificate", help = "Base64 encoded X509 certificate")
  private val certificate = Flag.value("")

  @JvmStatic
  fun main(args: Array<String>) {
    Flags.parse(args)
    val encodedCert: String = certificate.get()
    val base64EncodedCert =
      "-----BEGIN CERTIFICATE-----\n" + encodedCert + "\n-----END CERTIFICATE-----"
    val keyDescription = base64EncodedCert.asX509Certificate().keyDescription()
    println(keyDescription.prettyPrint())
  }

  fun KeyDescription.prettyPrint(): String = buildString {
    appendLine("KeyDescription:")
    appendLine("\tattestationVersion: $attestationVersion")
    appendLine("\tattestationSecurityLevel: $attestationSecurityLevel")
    appendLine("\tkeymasterVersion: $keymasterVersion")
    appendLine("\tkeymasterSecurityLevel: $keymasterSecurityLevel")
    appendLine("\tattestationChallenge: ${attestationChallenge.prettyPrinting()}")
    appendLine("\tuniqueId: ${uniqueId.prettyPrinting()}")
    appendLine("\tsoftwareEnforced: \n${softwareEnforced.prettyPrint()}")
    appendLine("\tteeEnforced: \n${teeEnforced.prettyPrint()}")
  }

  fun AuthorizationList.prettyPrint(): String {
    return buildString {
      if (purposes != null) appendLine("\t\tpurposes: $purposes")
      if (keySize != null) appendLine("\t\tkeySize: $keySize")
      if (algorithms != null) appendLine("\t\talgorithms: $algorithms")
      if (digests != null) appendLine("\t\tdigests: $digests")
      if (paddings != null) appendLine("\t\tpaddings: $paddings")
      if (ecCurve != null) appendLine("\t\tecCurve: $ecCurve")
      if (rsaPublicExponent != null) appendLine("\t\trsaPublicExponent: $rsaPublicExponent")
      if (activeDateTime != null) appendLine("\t\tactiveDateTime: $activeDateTime")
      if (originationExpireDateTime != null)
        appendLine("\t\toriginationExpireDateTime: $originationExpireDateTime")
      if (usageExpireDateTime != null) appendLine("\t\tusageExpireDateTime: $usageExpireDateTime")
      if (noAuthRequired != null) appendLine("\t\tnoAuthRequired: $noAuthRequired")
      if (userAuthType != null) appendLine("\t\tuserAuthType: $userAuthType")
      if (authTimeout != null) appendLine("\t\tauthTimeout: $authTimeout")
      if (trustedUserPresenceRequired != null)
        appendLine("\t\ttrustedUserPresenceRequired: $trustedUserPresenceRequired")
      if (unlockedDeviceRequired != null)
        appendLine("\t\tunlockedDeviceRequired: $unlockedDeviceRequired")
      if (creationDateTime != null) appendLine("\t\tcreationDateTime: $creationDateTime")
      if (origin != null) appendLine("\t\torigin: $origin")
      if (rollbackResistant != null) appendLine("\t\trollbackResistant: $rollbackResistant")
      if (rootOfTrust != null) append("\t\trootOfTrust:\n${rootOfTrust.prettyPrint()}")
      if (osVersion != null) appendLine("\t\tosVersion: $osVersion")
      if (osPatchLevel != null) appendLine("\t\tosPatchLevel: $osPatchLevel")
      if (attestationApplicationId != null)
        append("\t\tattestationApplicationId:\n${attestationApplicationId.prettyPrint()}")
      if (attestationIdBrand != null) appendLine("\t\tattestationIdBrand: $attestationIdBrand")
      if (attestationIdDevice != null) appendLine("\t\tattestationIdDevice: $attestationIdDevice")
      if (attestationIdProduct != null)
        appendLine("\t\tattestationIdProduct: $attestationIdProduct")
      if (attestationIdSerial != null) appendLine("\t\tattestationIdSerial: $attestationIdSerial")
      if (attestationIdImei != null) appendLine("\t\tattestationIdImei: $attestationIdImei")
      if (attestationIdMeid != null) appendLine("\t\tattestationIdMeid: $attestationIdMeid")
      if (attestationIdManufacturer != null)
        appendLine("\t\tattestationIdManufacturer: $attestationIdManufacturer")
      if (attestationIdModel != null) appendLine("\t\tattestationIdModel: $attestationIdModel")
      if (vendorPatchLevel != null) appendLine("\t\tvendorPatchLevel: $vendorPatchLevel")
      if (bootPatchLevel != null) appendLine("\t\tbootPatchLevel: $bootPatchLevel")
      if (attestationIdSecondImei != null)
        appendLine("\t\tattestationIdSecondImei: $attestationIdSecondImei")
      if (moduleHash != null) appendLine("\t\tmoduleHash: $moduleHash")
    }
  }

  fun AttestationApplicationId.prettyPrint(): String = buildString {
    appendLine("\t\t\tpackages: \n${packages.map { it.prettyPrint() }.joinToString("\n")}")
    append("\t\t\tsignatures: \n${signatures.map { it.prettyPrint() }.joinToString("\n")}")
  }

  fun ByteString.prettyPrint(): String = buildString { append("\t\t\t\t${prettyPrinting()}") }

  fun ByteString.prettyPrinting(): String =
    if (this.isEmpty) "\"\"" else joinToString("") { "%02x".format(it) }

  fun AttestationPackageInfo.prettyPrint(): String = buildString {
    append("\t\t\t\tname: $name\n")
    append("\t\t\t\tversion: $version")
  }

  fun RootOfTrust.prettyPrint(): String = buildString {
    appendLine("\t\t\tverifiedBootKey: ${verifiedBootKey.prettyPrinting()}")
    appendLine("\t\t\tdeviceLocked: $deviceLocked")
    appendLine("\t\t\tverifiedBootState: $verifiedBootState")
    appendLine("\t\t\tverifiedBootHash: ${verifiedBootHash?.prettyPrinting() ?: "\"\""}")
  }
}
