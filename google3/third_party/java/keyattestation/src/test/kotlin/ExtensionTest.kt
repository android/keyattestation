package com.google.wireless.android.security.attestationverifier

import com.google.common.truth.Truth.assertThat
import com.google.devtools.build.runtime.RunfilesPaths
import com.google.protobuf.ByteString
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import com.google.wireless.android.security.attestationverifier.testing.TestUtils.TESTDATA_PATH
import com.google.wireless.android.security.attestationverifier.testing.TestUtils.readCertPath
import com.google.wireless.android.security.attestationverifier.testing.toKeyDescription
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
  private val testData = RunfilesPaths.resolve(TESTDATA_PATH)

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
    PIXEL_3_SDK28("blueline", 28)
  }

  // TODO: b/374316734 - replace this test data with a certificate generated on a Pixel.
  @Test
  fun parseFrom_containsRollbackResistant_success() {
    val keyDescription =
      testData.resolve("rollback_resistant.pem").inputStream().asX509Certificate().keyDescription()
    assertThat(keyDescription.teeEnforced.rollbackResistant).isTrue()
  }

  @Test
  @Ignore("TODO: b/356172932 - Reenable test once enabling tag order validator is configurable.")
  fun parseFrom_tagsNotInAscendingOrder_Throws() {
    assertFailsWith<IllegalArgumentException> {
      readCertPath("invalid/tags_not_in_accending_order.pem").leafCert().keyDescription()
    }
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
        origin = 1.toBigInteger(),
        rollbackResistant = true,
        rootOfTrust =
          RootOfTrust(
            verifiedBootKey = ByteString.copyFromUtf8("verifiedBootKey"),
            deviceLocked = false,
            verifiedBootState = VerifiedBootState.UNVERIFIED,
            verifiedBootHash = ByteString.copyFromUtf8("verifiedBootHash"),
          ),
        osVersion = 11.toBigInteger(),
        osPatchLevel = 5.toBigInteger(),
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
        attestationIdManufacturer = "manufacturer",
        attestationIdModel = "model",
        vendorPatchLevel = 6.toBigInteger(),
        bootPatchLevel = 7.toBigInteger(),
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
        teeEnforced = authorizationList,
      )
    assertThat(KeyDescription.parseFrom(keyDescription.encodeToAsn1())).isEqualTo(keyDescription)
  }
}
