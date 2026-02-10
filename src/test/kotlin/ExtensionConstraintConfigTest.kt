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

import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ExtensionConstraintConfigTest {

  private companion object {
    val authorizationList =
      AuthorizationList(purposes = setOf(1.toBigInteger()), algorithms = 1.toBigInteger())

    fun createTestKeyDescription(
      attestationSecurityLevel: SecurityLevel,
      keyMintSecurityLevel: SecurityLevel,
    ) =
      KeyDescription(
        attestationVersion = 1.toBigInteger(),
        attestationSecurityLevel = attestationSecurityLevel,
        keyMintVersion = 1.toBigInteger(),
        keyMintSecurityLevel = keyMintSecurityLevel,
        attestationChallenge = ByteString.empty(),
        uniqueId = ByteString.empty(),
        softwareEnforced = authorizationList,
        hardwareEnforced = authorizationList,
      )
  }

  val keyDescriptionWithStrongBoxSecurityLevels =
    createTestKeyDescription(SecurityLevel.STRONG_BOX, SecurityLevel.STRONG_BOX)
  val keyDescriptionWithTeeSecurityLevels =
    createTestKeyDescription(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.TRUSTED_ENVIRONMENT)
  val keyDescriptionWithSoftwareSecurityLevels =
    createTestKeyDescription(SecurityLevel.SOFTWARE, SecurityLevel.SOFTWARE)
  val keyDescriptionWithMismatchedSecurityLevels =
    createTestKeyDescription(SecurityLevel.STRONG_BOX, SecurityLevel.TRUSTED_ENVIRONMENT)

  @Test
  fun ValidationLevelIsSatisfiedBy_strictWithExpectedValue() {
    val level = ValidationLevel.STRICT("foo")

    assertThat(level.isSatisfiedBy("foo")).isTrue()
    assertThat(level.isSatisfiedBy("bar")).isFalse()
    assertThat(level.isSatisfiedBy(null)).isFalse()
  }

  @Test
  fun ValidationLevelIsSatisfiedBy_notNull_allowsAnyValue() {
    val level = ValidationLevel.NOT_NULL

    assertThat(level.isSatisfiedBy("foo")).isTrue()
    assertThat(level.isSatisfiedBy(null)).isFalse()
  }

  @Test
  fun ValidationLevelIsSatisfiedBy_ignore_allowsAnyValue() {
    val level = ValidationLevel.IGNORE

    assertThat(level.isSatisfiedBy("foo")).isTrue()
    assertThat(level.isSatisfiedBy(null)).isTrue()
  }

  @Test
  fun SecurityLevelValidationLevelIsSatisfiedBy_strictWithExpectedValue() {
    val level = SecurityLevelValidationLevel.STRICT(SecurityLevel.STRONG_BOX)

    assertThat(level.isSatisfiedBy(keyDescriptionWithStrongBoxSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithTeeSecurityLevels)).isFalse()
    assertThat(level.isSatisfiedBy(keyDescriptionWithMismatchedSecurityLevels)).isFalse()
  }

  @Test
  fun SecurityLevelValidationLevelIsSatisfiedBy_notSoftware_allowsAnyNonSoftwareMatchingLevels() {
    val level = SecurityLevelValidationLevel.NOT_SOFTWARE

    assertThat(level.isSatisfiedBy(keyDescriptionWithStrongBoxSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithTeeSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithSoftwareSecurityLevels)).isFalse()
    assertThat(level.isSatisfiedBy(keyDescriptionWithMismatchedSecurityLevels)).isFalse()
  }

  @Test
  fun SecurityLevelValidationLevelIsSatisfiedBy_consistent_allowsAnyMatchingLevels() {
    val level = SecurityLevelValidationLevel.CONSISTENT

    assertThat(level.isSatisfiedBy(keyDescriptionWithStrongBoxSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithTeeSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithSoftwareSecurityLevels)).isTrue()
    assertThat(level.isSatisfiedBy(keyDescriptionWithMismatchedSecurityLevels)).isFalse()
  }

  @Test
  fun AuthorizationListOrderingIsSatisfiedBy_strictWithUnorderedTags_fails() {
    val ordering = TagOrderValidationLevel.STRICT

    assertThat(ordering.isSatisfiedBy(keyDescriptionWithStrongBoxSecurityLevels)).isTrue()
    assertThat(
        ordering.isSatisfiedBy(
          KeyDescription.parseFrom(
            readCertPath("invalid/tags_not_in_ascending_order.pem").leafCert()
          )
        )
      )
      .isFalse()
  }
}
