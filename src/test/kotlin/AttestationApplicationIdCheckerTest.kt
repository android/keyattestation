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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteStringUtf8
import java.math.BigInteger
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class AttestationApplicationIdCheckerTest {

  private companion object {
    val TEST_PACKAGE = AttestationPackageInfo("com.example.app", BigInteger.valueOf(10))
    val TEST_SIGNATURE = ByteString.copyFromUtf8("test-signature")
    val EXPECTED_APP_ID =
      AttestationApplicationId(packages = setOf(TEST_PACKAGE), signatures = setOf(TEST_SIGNATURE))
    val UNKNOWN_PACKAGE = AttestationPackageInfo("UnknownPackage", BigInteger.ONE)
    val MAX_OS_VERSION = BigInteger.valueOf(140000)
  }

  @Test
  fun strict_matchingAppId_returnsTrue() {
    val checker = AttestationApplicationIdChecker.STRICT(EXPECTED_APP_ID)
    val actualAppId =
      AttestationApplicationId(packages = setOf(TEST_PACKAGE), signatures = setOf(TEST_SIGNATURE))

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isTrue()
  }

  @Test
  fun strict_higherVersion_returnsTrue() {
    val checker = AttestationApplicationIdChecker.STRICT(EXPECTED_APP_ID)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.example.app", BigInteger.valueOf(11))),
        signatures = setOf(TEST_SIGNATURE),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isTrue()
  }

  @Test
  fun strict_noSignatureRequirements_returnsTrue() {
    val checker =
      AttestationApplicationIdChecker.STRICT(
        AttestationApplicationId(packages = setOf(TEST_PACKAGE), signatures = emptySet())
      )
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.example.app", BigInteger.valueOf(11))),
        signatures = setOf("totally-not-the-right-signature".toByteStringUtf8()),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isTrue()
  }

  @Test
  fun strict_lowerVersion_returnsFalse() {
    val checker = AttestationApplicationIdChecker.STRICT(EXPECTED_APP_ID)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.example.app", BigInteger.valueOf(9))),
        signatures = setOf(TEST_SIGNATURE),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isFalse()
  }

  @Test
  fun strict_mismatchedPackageName_returnsFalse() {
    val checker = AttestationApplicationIdChecker.STRICT(EXPECTED_APP_ID)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.other.app", BigInteger.valueOf(10))),
        signatures = setOf(TEST_SIGNATURE),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isFalse()
  }

  @Test
  fun strict_mismatchedSignature_returnsFalse() {
    val checker = AttestationApplicationIdChecker.STRICT(EXPECTED_APP_ID)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(TEST_PACKAGE),
        signatures = setOf(ByteString.copyFromUtf8("other-signature")),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isFalse()
  }

  @Test
  fun lenient_matchingAppId_returnsTrueRegardlessOfOsVersion() {
    val checker = AttestationApplicationIdChecker.LENIENT(EXPECTED_APP_ID, MAX_OS_VERSION)

    // Higher OS version with matching ID
    assertThat(checker.checkAttestationApplicationId(EXPECTED_APP_ID, BigInteger.valueOf(150000)))
      .isTrue()
    // Lower OS version with matching ID
    assertThat(checker.checkAttestationApplicationId(EXPECTED_APP_ID, BigInteger.valueOf(130000)))
      .isTrue()
  }

  @Test
  fun lenient_mismatchedAppId_withUnknownPackage_andLowerOrEqualOsVersion_returnsTrue() {
    val checker = AttestationApplicationIdChecker.LENIENT(EXPECTED_APP_ID, MAX_OS_VERSION)
    val actualAppId =
      AttestationApplicationId(packages = setOf(UNKNOWN_PACKAGE), signatures = setOf())

    // OS version equal to maxOsVersion
    assertThat(checker.checkAttestationApplicationId(actualAppId, MAX_OS_VERSION)).isTrue()
    // OS version strictly lower than maxOsVersion
    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(130000)))
      .isTrue()
  }

  @Test
  fun lenient_mismatchedAppId_withUnknownPackage_andHigherOsVersion_returnsFalse() {
    val checker = AttestationApplicationIdChecker.LENIENT(EXPECTED_APP_ID, MAX_OS_VERSION)
    val actualAppId =
      AttestationApplicationId(packages = setOf(UNKNOWN_PACKAGE), signatures = setOf())

    // OS version exceeds maxOsVersion
    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(150000)))
      .isFalse()
  }

  @Test
  fun lenient_mismatchedAppId_withoutUnknownPackage_andLowerOsVersion_returnsFalse() {
    val checker = AttestationApplicationIdChecker.LENIENT(EXPECTED_APP_ID, MAX_OS_VERSION)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.other.app", BigInteger.valueOf(10))),
        signatures = setOf(TEST_SIGNATURE),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(130000)))
      .isFalse()
  }

  @Test
  fun lenient_mismatchedAppId_withUnknownPackageWrongVersion_returnsFalse() {
    val checker = AttestationApplicationIdChecker.LENIENT(EXPECTED_APP_ID, MAX_OS_VERSION)
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("UnknownPackage", BigInteger.valueOf(2))),
        signatures = setOf(),
      )

    assertThat(checker.checkAttestationApplicationId(actualAppId, BigInteger.valueOf(130000)))
      .isFalse()
  }

  @Test
  fun none_alwaysReturnsTrue() {
    val checker = AttestationApplicationIdChecker.NONE
    val anyAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("arbitrary.app", BigInteger.valueOf(1))),
        signatures = setOf(ByteString.copyFromUtf8("arbitrary-sig")),
      )

    assertThat(checker.checkAttestationApplicationId(anyAppId, BigInteger.valueOf(123456))).isTrue()
    assertThat(
        checker.checkAttestationApplicationId(
          AttestationApplicationId(emptySet(), emptySet()),
          BigInteger.ZERO,
        )
      )
      .isTrue()
  }

  @Test
  fun hasUnknownPackage_withMatchingUnknownPackage_returnsTrue() {
    val appId =
      AttestationApplicationId(
        packages = setOf(TEST_PACKAGE, UNKNOWN_PACKAGE),
        signatures = emptySet(),
      )

    assertThat(AttestationApplicationIdChecker.hasUnknownPackage(appId)).isTrue()
  }

  @Test
  fun hasUnknownPackage_withWrongVersion_returnsFalse() {
    val appId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("UnknownPackage", BigInteger.valueOf(2))),
        signatures = emptySet(),
      )

    assertThat(AttestationApplicationIdChecker.hasUnknownPackage(appId)).isFalse()
  }

  @Test
  fun hasUnknownPackage_withoutUnknownPackage_returnsFalse() {
    val appId = AttestationApplicationId(packages = setOf(TEST_PACKAGE), signatures = emptySet())

    assertThat(AttestationApplicationIdChecker.hasUnknownPackage(appId)).isFalse()
  }

  @Test
  fun hasUnknownPackage_emptyPackages_returnsFalse() {
    val appId = AttestationApplicationId(packages = emptySet(), signatures = emptySet())

    assertThat(AttestationApplicationIdChecker.hasUnknownPackage(appId)).isFalse()
  }
}
