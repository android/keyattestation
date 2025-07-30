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

import com.android.keyattestation.verifier.testing.Chains
import com.android.keyattestation.verifier.testing.TestUtils.TESTDATA_PATH
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.android.keyattestation.verifier.testing.toKeyDescription
import com.google.common.truth.Truth.assertThat

import com.google.protobuf.ByteString
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import java.time.YearMonth
import kotlin.io.path.Path
import kotlin.io.path.inputStream
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.readText
import kotlin.io.path.reader
import kotlin.test.assertFailsWith
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(TestParameterInjector::class)
class ExtensionTest {
  private val testData = Path("testdata")

  @Test
  fun parseFrom_provisioningInfoFromAttestationCert_success() {
    // The provisioning info in `validRemotelyProvisioned` from CertLists.kt
    val expectedProvisioningInfo =
      ProvisioningInfoMap(
        certificatesIssued = 1,
      )
    val provisioningInfo =
      ProvisioningInfoMap.parseFrom(Chains.validRemotelyProvisioned.attestationCert())
    assertThat(provisioningInfo).isEqualTo(expectedProvisioningInfo)
  }

  @Test
  fun parseFrom_success(@TestParameter testCase: TestCase) {
    val path = testData.resolve("${testCase.model}/sdk${testCase.sdk}")
    val chainMap =
      path.listDirectoryEntries("*.pem").map {
        Pair(it, Path("${it.parent}/${it.nameWithoutExtension}.json"))
      }

    for ((pemPath, jsonPath) in chainMap) {
      assertThat(readCertPath(pemPath.reader()).leafCert().keyDescription())
        .isEqualTo(jsonPath.readText().toKeyDescription())
    }
  }

  enum class TestCase(val model: String, val sdk: Int) {
    PIXEL_SDK29("marlin", 29),
    PIXEL_3_SDK28("blueline", 28),
    PIXEL_8A_SDK34("akita", 34),
  }

  @Test
  @Ignore("b/399272143 - unignore in cl/735538301")
  fun parseFrom_containsAllowWhileOnBody_success() {
    val unused =
      testData.resolve("allow_while_on_body.pem").inputStream().asX509Certificate().keyDescription()
    // assertThat(keyDescription.hardwareEnforced.allowWhileOnBody).isTrue()
  }

  @Test
  @Ignore("TODO: b/356172932 - Reenable test once enabling tag order validator is configurable.")
  fun parseFrom_tagsNotInAscendingOrder_Throws() {
    assertFailsWith<IllegalArgumentException> {
      readCertPath("invalid/tags_not_in_accending_order.pem").leafCert().keyDescription()
    }
  }

  @Test
  fun parseFrom_invalidPatchLevel_returnsNull(
    @TestParameter("202400", "00000000", "2000231") patchLevel: String
  ) {
    assertThat(PatchLevel.from(patchLevel)).isNull()
  }

  @Test
  fun keyDescription_encodeToAsn1_expectedResult() {
    val authorizationList =
      AuthorizationList(
        purposes = setOf(1.toBigInteger()),
        algorithms = 1.toBigInteger(),
        keySize = 2.toBigInteger(),
        digests = setOf(1.toBigInteger()),
        paddings = setOf(1.toBigInteger()),
        ecCurve = 3.toBigInteger(),
        rsaPublicExponent = 4.toBigInteger(),
        activeDateTime = 5.toBigInteger(),
        originationExpireDateTime = 6.toBigInteger(),
        usageExpireDateTime = 7.toBigInteger(),
        noAuthRequired = true,
        userAuthType = 1.toBigInteger(),
        authTimeout = 9.toBigInteger(),
        trustedUserPresenceRequired = true,
        creationDateTime = 10.toBigInteger(),
        origin = Origin.GENERATED,
        rollbackResistant = true,
        rootOfTrust =
          RootOfTrust(
            verifiedBootKey = ByteString.copyFromUtf8("verifiedBootKey"),
            deviceLocked = false,
            verifiedBootState = VerifiedBootState.UNVERIFIED,
            verifiedBootHash = ByteString.copyFromUtf8("verifiedBootHash"),
          ),
        osVersion = 11.toBigInteger(),
        osPatchLevel = PatchLevel(yearMonth = YearMonth.of(2024, 4)),
        attestationApplicationId =
          AttestationApplicationId(
            packages = setOf(AttestationPackageInfo(name = "name", version = 1.toBigInteger())),
            signatures = setOf(ByteString.copyFromUtf8("signature")),
          ),
        attestationIdBrand = "brand",
        attestationIdDevice = "device",
        attestationIdProduct = "product",
        attestationIdSerial = "serial",
        attestationIdImei = "imei",
        attestationIdMeid = "meid",
        attestationIdManufacturer = "attestationIdManufacturer",
        attestationIdModel = "model",
        vendorPatchLevel = PatchLevel(YearMonth.of(2024, 4), 5),
        bootPatchLevel = PatchLevel(YearMonth.of(2024, 4), 5),
        attestationIdSecondImei = "secondImei",
      )
    val keyDescription =
      KeyDescription(
        attestationVersion = 1.toBigInteger(),
        attestationSecurityLevel = SecurityLevel.SOFTWARE,
        keymasterVersion = 1.toBigInteger(),
        keymasterSecurityLevel = SecurityLevel.SOFTWARE,
        attestationChallenge = ByteString.empty(),
        uniqueId = ByteString.empty(),
        softwareEnforced = authorizationList,
        hardwareEnforced = authorizationList,
      )
    assertThat(KeyDescription.parseFrom(keyDescription.encodeToAsn1())).isEqualTo(keyDescription)
  }
}
